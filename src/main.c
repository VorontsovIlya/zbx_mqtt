#include <mosquitto.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <signal.h>

#include "common.h"

#include "threads.h"
#include "comms.h"
#include "cfg.h"
#include "log.h"
#include "zbxgetopt.h"
#include "zbxjson.h"
#include "../libs/zbxcrypto/tls.h"

#ifndef _WINDOWS
#       include "zbxnix.h"
#endif

#define SUCCEED_PARTIAL 2

int keepalive = 30;

const char *progname = NULL;
const char title_message[] = "zbx_mqtt";
const char syslog_app_name[] = "zbx_mqtt";

const char *usage_message[] = { "-c config-file", NULL };

unsigned char program_type = ZBX_PROGRAM_TYPE_SENDER;

const char *help_message[] = {
    "Utility for sending monitoring data to Zabbix server or proxy.",
    "General options:",
    "  -c --config config-file    Absolute path to configuration file",
    NULL /* end of text */
};

/* TLS parameters */
unsigned int configured_tls_connect_mode = ZBX_TCP_SEC_UNENCRYPTED;
unsigned int configured_tls_accept_modes = ZBX_TCP_SEC_UNENCRYPTED; /* not used in zabbix_sender, just for */

int CONFIG_PASSIVE_FORKS = 0; /* not used in zabbix_sender, just for linking with tls.c */
int CONFIG_ACTIVE_FORKS = 0; /* not used in zabbix_sender, just for linking with tls.c */

/* sending a huge amount of values in a single connection is likely to */
/* take long and hit timeout, so we limit values to 250 per connection */
#define VALUES_MAX      250

/* COMMAND LINE OPTIONS */

/* long options */
static struct zbx_option longopts[] = { { "config", 1, NULL, 'c' }, { NULL } };

static char shortopts[] = "c:vhV";

static int CONFIG_LOG_LEVEL = LOG_LEVEL_CRIT;

static char *CONFIG_SOURCE_IP = NULL;
static char *ZABBIX_SERVER = NULL;
unsigned short ZABBIX_SERVER_PORT = 0;
static char *ZABBIX_HOSTNAME = NULL;
static char *MQTT_SERVER = NULL;
static char *MQTT_ID = NULL;
static char *DEBUG = NULL;
static char *BROKER_NAME = NULL;

#if !defined(_WINDOWS)
static void send_signal_handler(int sig) {
  if (SIGALRM == sig)
    zabbix_log(LOG_LEVEL_WARNING, "timeout while executing operation");

  /* Calling _exit() to terminate the process immediately is important. See ZBX-5732 for details. */
  _exit(EXIT_FAILURE);
}
#endif

typedef struct {
  char *source_ip;
  char *server;
  unsigned short port;
  struct zbx_json json;
  int sync_timestamp;
} ZBX_THREAD_SENDVAL_ARGS;

/******************************************************************************
 *                                                                            *
 * Function: update_exit_status                                               *
 *                                                                            *
 * Purpose: manage exit status updates after batch sends                      *
 *                                                                            *
 * Comments: SUCCEED_PARTIAL status should be sticky in the sense that        *
 *           SUCCEED statuses that come after should not overwrite it         *
 *                                                                            *
 ******************************************************************************/
static int update_exit_status(int old_status, int new_status) {
  if (FAIL == old_status || FAIL == new_status
      || (unsigned char) FAIL == new_status)
    return FAIL;

  if (SUCCEED == old_status)
    return new_status;

  if (SUCCEED_PARTIAL == old_status)
    return old_status;

  THIS_SHOULD_NEVER_HAPPEN;
  return FAIL;
}

/******************************************************************************
 *                                                                            *
 * Function: check_response                                                   *
 *                                                                            *
 * Purpose: Check whether JSON response is SUCCEED                            *
 *                                                                            *
 * Parameters: JSON response from Zabbix trapper                              *
 *                                                                            *
 * Return value:  SUCCEED - processed successfused -i -- 's/foo/bar/g' *lly                            *
 *                FAIL - an error occurred                                    *
 *                SUCCEED_PARTIAL - the sending operation was completed       *
 *                successfully, but processing of at least one value failed   *
 *                                                                            *
 * Author: Alexei Vladishev                                                   *
 *                                                                            *
 * Comments: active agent has almost the same function!                       *
 *                                                                            *
 ******************************************************************************/
static int check_response(char *response) {
  struct zbx_json_parse jp;
  char value[MAX_STRING_LEN];
  char info[MAX_STRING_LEN];
  int ret;

  ret = zbx_json_open(response, &jp);

  if (SUCCEED == ret)
    ret = zbx_json_value_by_name(&jp, ZBX_PROTO_TAG_RESPONSE, value,
        sizeof(value));

  if (SUCCEED == ret && 0 != strcmp(value, ZBX_PROTO_VALUE_SUCCESS))
    ret = FAIL;

  if (SUCCEED == ret
      && SUCCEED
          == zbx_json_value_by_name(&jp, ZBX_PROTO_TAG_INFO, info,
              sizeof(info))) {
    int failed;

    //printf("info from server: \"%s\"\n", info);

    if (NULL != DEBUG)
      zabbix_log(LOG_LEVEL_INFORMATION, "info from server: \"%s\"", info);

    fflush(stdout);

    if (1 == sscanf(info, "processed: %*d; failed: %d", &failed) && 0 < failed)
      ret = SUCCEED_PARTIAL;
  }

  return ret;
}

static ZBX_THREAD_ENTRY(send_value, args) {
  ZBX_THREAD_SENDVAL_ARGS *sendval_args;
  int tcp_ret, ret = FAIL;
  char *tls_arg1, *tls_arg2;
  zbx_socket_t sock;

  assert(args);
  assert(((zbx_thread_args_t * )args)->args);

  sendval_args = (ZBX_THREAD_SENDVAL_ARGS *) ((zbx_thread_args_t *) args)->args;

#if !defined(_WINDOWS)
  signal(SIGINT, send_signal_handler);
  signal(SIGTERM, send_signal_handler);
  signal(SIGQUIT, send_signal_handler);
  signal(SIGALRM, send_signal_handler);
#endif
  switch (configured_tls_connect_mode) {
  case ZBX_TCP_SEC_UNENCRYPTED:
    tls_arg1 = NULL;
    tls_arg2 = NULL;
    break;
  default:
    THIS_SHOULD_NEVER_HAPPEN;
    goto out;
  }

  if (SUCCEED
      == (tcp_ret = zbx_tcp_connect(&sock, CONFIG_SOURCE_IP,
          sendval_args->server, sendval_args->port,
          GET_SENDER_TIMEOUT, configured_tls_connect_mode, tls_arg1, tls_arg2))) {
    if (1 == sendval_args->sync_timestamp) {
      zbx_timespec_t ts;

      zbx_timespec(&ts);

      zbx_json_adduint64(&sendval_args->json, ZBX_PROTO_TAG_CLOCK, ts.sec);
      zbx_json_adduint64(&sendval_args->json, ZBX_PROTO_TAG_NS, ts.ns);
    }

    if (SUCCEED == (tcp_ret = zbx_tcp_send(&sock, sendval_args->json.buffer))) {
      if (SUCCEED == (tcp_ret = zbx_tcp_recv(&sock))) {
        zabbix_log(LOG_LEVEL_DEBUG, "answer [%s]", sock.buffer);
        if (NULL == sock.buffer || FAIL == (ret = check_response(sock.buffer)))
          zabbix_log(LOG_LEVEL_WARNING, "incorrect answer from server [%s]",
              sock.buffer);
      }
    }

    zbx_tcp_close(&sock);
  }

  if (FAIL == tcp_ret)
    zabbix_log(LOG_LEVEL_DEBUG, "send value error: %s", zbx_socket_strerror());
  out:
  zbx_thread_exit(ret);
}

static void zbx_fill_from_config_file(char **dst, char *src) {
  /* helper function, only for TYPE_STRING configuration parameters */

  if (NULL != src) {
    if (NULL == *dst)
      *dst = zbx_strdup(*dst, src);

    zbx_free(src);
  }
}

static void zbx_load_config(const char *config_file) {
  char *cfg_source_ip = NULL, *cfg_active_hosts = NULL, *cfg_hostname = NULL,
      *cfg_mqtt = NULL, *cfg_mqttid = NULL, *r = NULL, *cfg_logfile = NULL,
      *cfg_debug = 0, *cfg_brokername = 0;

  struct cfg_line cfg[] = {
  /* PARAMETER, VAR, TYPE, MANDATORY, MIN, MAX */
  { "SourceIP", &cfg_source_ip, TYPE_STRING, PARM_OPT, 0, 0 }, { "ServerActive",
      &cfg_active_hosts, TYPE_STRING_LIST, PARM_OPT, 0, 0 }, { "Hostname",
      &cfg_hostname, TYPE_STRING, PARM_OPT, 0, 0 }, { "MQTT", &cfg_mqtt,
  TYPE_STRING, PARM_OPT, 0, 0 }, { "MQTTID", &cfg_mqttid, TYPE_STRING,
  PARM_OPT, 0, 0 },
      { "LogFile", &CONFIG_LOG_FILE, TYPE_STRING, PARM_OPT, 0, 0 }, {
          "LogFileSize", &CONFIG_LOG_FILE_SIZE, TYPE_INT, PARM_OPT, 0, 1024 }, {
          "Debug", &DEBUG, TYPE_STRING, PARM_OPT, 0, 1024 }, { "BrokerName",
          &BROKER_NAME,
          TYPE_STRING, PARM_OPT, 0, 1024 }, { NULL } };

  if (NULL == config_file)
    return;

  /* do not complain about unknown parameters in agent configuration file */
  parse_cfg_file(config_file, cfg, ZBX_CFG_FILE_REQUIRED, ZBX_CFG_NOT_STRICT);

  zbx_fill_from_config_file(&CONFIG_SOURCE_IP, cfg_source_ip);

  if (NULL == ZABBIX_SERVER) {
    if (NULL != cfg_active_hosts && '\0' != *cfg_active_hosts) {
      unsigned short cfg_server_port = 0;

      if (NULL != (r = strchr(cfg_active_hosts, ',')))
        *r = '\0';

      if (SUCCEED
          != parse_serveractive_element(cfg_active_hosts, &ZABBIX_SERVER,
              &cfg_server_port, 0)) {
        zbx_error(
            "error parsing \"ServerActive\" option: address \"%s\" is invalid",
            cfg_active_hosts);
        exit(EXIT_FAILURE);
      }

      if (0 == ZABBIX_SERVER_PORT && 0 != cfg_server_port)
        ZABBIX_SERVER_PORT = cfg_server_port;
    }
  }
  zbx_free(cfg_active_hosts);

  zbx_fill_from_config_file(&ZABBIX_HOSTNAME, cfg_hostname);
  zbx_fill_from_config_file(&MQTT_SERVER, cfg_mqtt);
  zbx_fill_from_config_file(&MQTT_ID, cfg_mqttid);
  zbx_fill_from_config_file(&CONFIG_LOG_FILE, cfg_logfile);
  zbx_fill_from_config_file(&DEBUG, cfg_debug);
  zbx_fill_from_config_file(&BROKER_NAME, cfg_brokername);
}

static void parse_commandline(int argc, char **argv) {
  char ch;
  unsigned short opt_count[256] = { 0 };

  /* parse the command-line */
  while ((char) EOF
      != (ch = (char) zbx_getopt_long(argc, argv, shortopts, longopts,
      NULL))) {
    opt_count[(unsigned char) ch]++;

    switch (ch) {
    case 'c':
      if (NULL == CONFIG_FILE)
        CONFIG_FILE = zbx_strdup(CONFIG_FILE, zbx_optarg);
      break;
    default:
      usage();
      exit(EXIT_FAILURE);
      break;
    }
  }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////

zbx_thread_args_t thread_args;
ZBX_THREAD_SENDVAL_ARGS sendval_args;

void my_message_callback(struct mosquitto *mosq, void *userdata,
    const struct mosquitto_message *message) {
  int succeed_count = 0, ret = FAIL, i = 0;
  char host[255], item[255];
  memset(&host[0], 0, sizeof(host));
  memset(&item[0], 0, sizeof(item));

//  if (NULL != DEBUG) {
    if (message->payloadlen) {
      zabbix_log(LOG_LEVEL_INFORMATION, "%s %s", message->topic, message->payload);
    } else {
      zabbix_log(LOG_LEVEL_INFORMATION, "%s (null)", message->topic);
    }
//  }

  sscanf(message->topic, "/%*[hostrvice]/%[A-z0-9]/%s", host, item);
  if (sscanf(message->topic, "$SYS/%s", item)) {
    //host = MQTT_SERVER;
    if (NULL == BROKER_NAME)
      zbx_strlcpy(host, MQTT_SERVER, strlen(MQTT_SERVER) + 1);
    else
      zbx_strlcpy(host, BROKER_NAME, strlen(BROKER_NAME) + 1);
  }

  while (item[i] != '\0') {
    if (item[i] == '/')
      item[i] = '.';
    if (item[i] == ' ')
      item[i] = '_';
    i++;
  }

  if (NULL != DEBUG) {
    zabbix_log(LOG_LEVEL_INFORMATION, "Host = %s", host);
    zabbix_log(LOG_LEVEL_INFORMATION, "Item = %s", item);
    zabbix_log(LOG_LEVEL_INFORMATION, "Msg = %s", message->payload);
  }

  zbx_json_init(&sendval_args.json, ZBX_JSON_STAT_BUF_LEN);
  zbx_json_addstring(&sendval_args.json, ZBX_PROTO_TAG_REQUEST,
  ZBX_PROTO_VALUE_SENDER_DATA, ZBX_JSON_TYPE_STRING);
  zbx_json_addarray(&sendval_args.json, ZBX_PROTO_TAG_DATA);

  ret = SUCCEED;
  zbx_json_addobject(&sendval_args.json, NULL);

  zbx_json_addstring(&sendval_args.json, ZBX_PROTO_TAG_HOST, host,
      ZBX_JSON_TYPE_STRING);

  zbx_json_addstring(&sendval_args.json, ZBX_PROTO_TAG_KEY, item,
      ZBX_JSON_TYPE_STRING);

  zbx_json_addstring(&sendval_args.json, ZBX_PROTO_TAG_VALUE, message->payload,
      ZBX_JSON_TYPE_STRING);

  zbx_json_close(&sendval_args.json);
  succeed_count++;
  ret = update_exit_status(ret,
      zbx_thread_wait(zbx_thread_start(send_value, &thread_args)));
  zbx_json_free(&sendval_args.json);

  fflush(stdout);
}

void my_connect_callback(struct mosquitto *mosq, void *userdata, int result) {
  if (!result) {
    /* Subscribe to broker information topics on successful connect. */
    mosquitto_subscribe(mosq, NULL, "$SYS/#", 2);
    mosquitto_subscribe(mosq, NULL, "/host/#", 2);
    mosquitto_subscribe(mosq, NULL, "/service/#", 2);
  } else {
    zabbix_log(LOG_LEVEL_ERR, "Connect failed");
  }
}

void my_subscribe_callback(struct mosquitto *mosq, void *userdata, int mid,
    int qos_count, const int *granted_qos) {

//  printf("Subscribed (mid: %d): %d", mid, granted_qos[0]);
//  for (i = 1; i < qos_count; i++) {
//    printf(", %d", granted_qos[i]);
//  }
//  printf("\n");
}

void my_log_callback(struct mosquitto *mosq, void *userdata, int level,
    const char *str) {
  /* Pring all log messages regardless of level. */
  if (NULL != DEBUG)
    zabbix_log(LOG_LEVEL_INFORMATION, "%s", str);
}

int main(int argc, char **argv) {
  int port = 1883;
  int keepalive = 60;
  bool clean_session = true;
  struct mosquitto *mosq = NULL;

  progname = get_program_name(argv[0]);
  parse_commandline(argc, argv);

  if (argc != 3) {
    printf("Config file not defined, use option -c . Example: zbx_mqtt -c zbx_mqtt.conf\n");
    exit(1);
  }

  zbx_load_config(CONFIG_FILE);
  zabbix_open_log(LOG_TYPE_FILE, CONFIG_LOG_LEVEL, CONFIG_LOG_FILE);

  if (NULL == ZABBIX_SERVER)
    zabbix_log(LOG_LEVEL_CRIT, "'ServerActive' parameter required");
  else
    zabbix_log(LOG_LEVEL_INFORMATION, "Zabbix server = %s", ZABBIX_SERVER);

  if (0 == ZABBIX_SERVER_PORT)
    ZABBIX_SERVER_PORT = ZBX_DEFAULT_SERVER_PORT;

  if (MIN_ZABBIX_PORT > ZABBIX_SERVER_PORT)
    zabbix_log(LOG_LEVEL_CRIT, "Incorrect port number [%d]. Allowed [%d:%d]",
        (int )ZABBIX_SERVER_PORT, (int)MIN_ZABBIX_PORT, (int)MAX_ZABBIX_PORT);

  zabbix_log(LOG_LEVEL_INFORMATION, "Zabbix server port = %d",
      ZABBIX_SERVER_PORT);

  thread_args.server_num = 0;
  thread_args.args = &sendval_args;

  sendval_args.server = ZABBIX_SERVER;
  sendval_args.port = ZABBIX_SERVER_PORT;

  zabbix_log(LOG_LEVEL_INFORMATION, "MQTT server = %s", MQTT_SERVER);

  mosquitto_lib_init();
  mosq = mosquitto_new(MQTT_ID, clean_session, NULL);
  if (!mosq) {
    fprintf(stderr, "Error: Out of memory.\n");
    return 1;
  }
  mosquitto_log_callback_set(mosq, my_log_callback);
  mosquitto_connect_callback_set(mosq, my_connect_callback);
  mosquitto_message_callback_set(mosq, my_message_callback);
  mosquitto_subscribe_callback_set(mosq, my_subscribe_callback);

  if (mosquitto_connect(mosq, MQTT_SERVER, port, keepalive)) {
    fprintf(stderr, "Unable to connect.\n");
    return 1;
  }

  mosquitto_loop_forever(mosq, -1, 1);

  mosquitto_destroy(mosq);
  mosquitto_lib_cleanup();
  return 0;

  return 0;
}
