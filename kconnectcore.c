#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_EVENTS 60
#define LINE_BUF 512
#define MAX_IP 46
#define MAX_COMM 17
#define MAX_PROTO 6

#define CLR_RESET "\033[0m"
#define CLR_BOLD "\033[1m"
#define CLR_DIM "\033[2m"
#define CLR_RED "\033[31m"
#define CLR_GREEN "\033[32m"
#define CLR_YELLOW "\033[33m"
#define CLR_CYAN "\033[36m"
#define CLR_MAGENTA "\033[35m"
#define CLR_WHITE "\033[37m"

#define CURSOR_HOME "\033[H"
#define CLEAR_SCREEN "\033[2J"
#define CLEAR_LINE "\033[2K\r"

typedef struct {
  int pid;
  char comm[MAX_COMM];
  char proto[MAX_PROTO];
  char daddr[MAX_IP];
  int dport;
  int sport;
} Connection;

static Connection events[MAX_EVENTS];
static int head = 0;
static int count = 0;

#define MAX_PROCS 64
static char proc_names[MAX_PROCS][MAX_COMM];
static int proc_counts[MAX_PROCS];
static int proc_num = 0;

static long total_connections = 0;

static volatile int running = 1;

void sigint_handler(int sig) {
  (void)sig;
  running = 0;
}

void increment_proc_count(const char *name) {
  for (int i = 0; i < proc_num; i++) {
    if (strncmp(proc_names[i], name, MAX_COMM - 1) == 0) {
      proc_counts[i]++;
      return;
    }
  }
  if (proc_num < MAX_PROCS) {
    strncpy(proc_names[proc_num], name, MAX_COMM - 1);
    proc_names[proc_num][MAX_COMM - 1] = '\0';
    proc_counts[proc_num] = 1;
    proc_num++;
  }
}

void print_header(void) {
  printf("%s%-8s %-16s %-6s %-20s %-7s %-7s%s\n", CLR_BOLD, "PID", "PROCESS",
         "PROTO", "DEST IP", "DPORT", "SPORT", CLR_RESET);

  printf("%s", CLR_DIM);
  for (int i = 0; i < 70; i++)
    printf("─");
  printf("%s\n", CLR_RESET);
}

void print_connection(const Connection *c) {
  const char *proto_color =
      (strncmp(c->proto, "TCP", 3) == 0) ? CLR_CYAN : CLR_MAGENTA;
  const char *port_color = (c->dport < 1024) ? CLR_RED : CLR_GREEN;

  printf("%-8d "
         "%s%-16s%s "
         "%s%-6s%s "
         "%-20s "
         "%s%-7d%s "
         "%s%-7d%s\n",
         c->pid, CLR_DIM, c->comm, CLR_RESET, proto_color, c->proto, CLR_RESET,
         c->daddr, port_color, c->dport, CLR_RESET, CLR_DIM, c->sport,
         CLR_RESET);
}

void print_summary(void) {

  int top_idx[5];
  int top_n = 0;
  int used[MAX_PROCS] = {0};

  for (int i = 0; i < 5 && i < proc_num; i++) {
    int best = -1;
    for (int j = 0; j < proc_num; j++) {
      if (!used[j] && (best == -1 || proc_counts[j] > proc_counts[best])) {
        best = j;
      }
    }
    if (best >= 0) {
      top_idx[top_n++] = best;
      used[best] = 1;
    }
  }

  printf("%s", CLR_DIM);
  for (int i = 0; i < 70; i++)
    printf("─");
  printf("%s\n", CLR_RESET);

  printf("%sTop processes:%s ", CLR_BOLD, CLR_RESET);
  for (int i = 0; i < top_n; i++) {
    printf("%s%s%s %s%d%s  ", CLR_CYAN, proc_names[top_idx[i]], CLR_RESET,
           CLR_DIM, proc_counts[top_idx[i]], CLR_RESET);
  }
  printf("\n");
  printf("%sTotal: %ld connections%s\n", CLR_DIM, total_connections, CLR_RESET);
}

int parse_line(char *buf, Connection *out) {

  if (buf[0] == '#' || buf[0] == '\n' || buf[0] == '\r')
    return 0;

  char *tok;

  tok = strtok(buf, "|");
  if (!tok)
    return 0;
  out->pid = atoi(tok);

  tok = strtok(NULL, "|");
  if (!tok)
    return 0;
  strncpy(out->comm, tok, MAX_COMM - 1);
  out->comm[MAX_COMM - 1] = '\0';

  tok = strtok(NULL, "|");
  if (!tok)
    return 0;
  strncpy(out->proto, tok, MAX_PROTO - 1);
  out->proto[MAX_PROTO - 1] = '\0';

  tok = strtok(NULL, "|");
  if (!tok)
    return 0;
  strncpy(out->daddr, tok, MAX_IP - 1);
  out->daddr[MAX_IP - 1] = '\0';

  tok = strtok(NULL, "|");
  if (!tok)
    return 0;
  out->dport = atoi(tok);

  tok = strtok(NULL, "|");
  if (!tok)
    return 0;
  out->sport = atoi(tok);

  return 1;
}

int main(void) {
  char buf[LINE_BUF];

  signal(SIGINT, sigint_handler);

  setbuf(stdout, NULL);

  printf("%s", CLEAR_SCREEN);
  printf("%sKConnect Core%s — bpftrace + C display\n", CLR_BOLD, CLR_RESET);
  printf("%sWaiting for connections...%s\n\n", CLR_DIM, CLR_RESET);
  print_header();

  while (running && fgets(buf, sizeof(buf), stdin)) {
    Connection c;

    if (!parse_line(buf, &c))
      continue;

    events[head] = c;
    head = (head + 1) % MAX_EVENTS;
    if (count < MAX_EVENTS)
      count++;

    total_connections++;
    increment_proc_count(c.comm);

    print_connection(&c);

    if (total_connections % 10 == 0) {
      print_summary();
      print_header();
    }
  }

  printf("\n");
  print_summary();
  printf("\n%sKConnect Core stopped.%s\n", CLR_DIM, CLR_RESET);

  return 0;
}
