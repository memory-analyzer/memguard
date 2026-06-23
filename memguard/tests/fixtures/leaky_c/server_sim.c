/*
 * server_sim.c — Simulated HTTP server with 10 real-world memory bugs
 * Compile: gcc -g -O0 -pthread -o /tmp/server_sim server_sim.c
 * Scan:    memguard scan /tmp/server_sim --tools valgrind,helgrind
 * Static:  memguard scan <dir containing this file> --tools infer
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* ──────────────── Data Structures ──────────────── */

typedef struct {
    char *method;     /* GET, POST, etc. */
    char *path;       /* /api/users */
    char *body;       /* request body */
    int   content_len;
} HttpRequest;

typedef struct LogEntry {
    char message[256];
    struct LogEntry *next;
} LogEntry;

typedef struct {
    int   active_connections;
    int   total_requests;
    char *server_name;
    LogEntry *log_head;
    pthread_mutex_t stats_lock;
} ServerState;

/* ──────────────── BUG 1: Buffer overflow in header parsing ──────────────── */
HttpRequest *parse_request(const char *raw) {
    HttpRequest *req = malloc(sizeof(HttpRequest));
    if (!req) return NULL;

    char method_buf[8];  /* Too small for "OPTIONS\0" or "DELETE\0" */
    /* BUG: no bounds check — "OPTIONS" overflows method_buf */
    sscanf(raw, "%s", method_buf);
    req->method = strdup(method_buf);

    /* BUG 2: path never initialized on malformed input */
    char *space = strchr(raw, ' ');
    if (space) {
        char *path_start = space + 1;
        char *path_end = strchr(path_start, ' ');
        if (path_end) {
            int len = path_end - path_start;
            req->path = malloc(len + 1);
            strncpy(req->path, path_start, len);
            req->path[len] = '\0';
        }
        /* BUG: if no second space, req->path is uninitialized garbage */
    }

    req->body = NULL;
    req->content_len = 0;
    return req;
}

/* ──────────────── BUG 3: Double free in cleanup ──────────────── */
void free_request(HttpRequest *req) {
    if (!req) return;
    free(req->method);
    free(req->path);
    free(req->body);
    free(req);
}

void handle_and_free(HttpRequest *req) {
    printf("Handling: %s %s\n", req->method, req->path ? req->path : "/");
    free_request(req);
    /* BUG: caller also calls free_request → double free */
}

/* ──────────────── BUG 4: Use-after-free in logging ──────────────── */
char *format_log(const char *method, const char *path) {
    char *buf = malloc(512);
    if (!buf) return NULL;
    snprintf(buf, 512, "[%s] %s", method, path);
    return buf;
}

void log_request(ServerState *state, HttpRequest *req) {
    char *msg = format_log(req->method, req->path ? req->path : "/");
    free(msg);
    /* BUG: use-after-free — msg is accessed after free */
    LogEntry *entry = malloc(sizeof(LogEntry));
    if (entry) {
        strncpy(entry->message, msg, 255);  /* UAF: msg already freed */
        entry->message[255] = '\0';
        entry->next = state->log_head;
        state->log_head = entry;
    }
}

/* ──────────────── BUG 5: Memory leak in error path ──────────────── */
int process_body(HttpRequest *req, const char *data) {
    char *decoded = malloc(strlen(data) + 1);
    if (!decoded) return -1;
    strcpy(decoded, data);

    char *validated = malloc(strlen(decoded) * 2);
    if (!validated) {
        /* BUG: decoded is leaked on this error path */
        return -1;
    }

    /* process... */
    snprintf(validated, strlen(decoded) * 2, "OK:%s", decoded);

    req->body = validated;
    req->content_len = strlen(validated);
    free(decoded);
    return 0;
}

/* ──────────────── BUG 6: Race condition on shared counter ──────────────── */
static ServerState g_server = {0};

void *worker_thread(void *arg) {
    int id = *(int *)arg;
    for (int i = 0; i < 1000; i++) {
        /* BUG: no mutex around shared state */
        g_server.active_connections++;
        g_server.total_requests++;
        g_server.active_connections--;
    }
    return NULL;
}

/* ──────────────── BUG 7: Stack buffer overflow ──────────────── */
void build_response(const char *body, char *out, int out_size) {
    char header[64];
    /* BUG: if body is long, sprintf overflows header[] */
    sprintf(header, "Content-Length: %lu\r\n", strlen(body));

    /* Safe copy to output */
    snprintf(out, out_size, "HTTP/1.1 200 OK\r\n%s\r\n%s", header, body);
}

/* ──────────────── BUG 8: Leak of log entries (never freed) ──────────────── */
void add_log(ServerState *state, const char *msg) {
    LogEntry *entry = malloc(sizeof(LogEntry));
    if (!entry) return;
    strncpy(entry->message, msg, 255);
    entry->message[255] = '\0';
    entry->next = state->log_head;
    state->log_head = entry;
    /* BUG: log entries accumulate and are never freed */
}

/* ──────────────── BUG 9: File descriptor leak ──────────────── */
int read_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "error")) {
            /* BUG: early return without fclose */
            return -2;
        }
    }
    fclose(f);
    return 0;
}

/* ──────────────── BUG 10: Null dereference on allocation failure ──────────────── */
void init_server(ServerState *state, const char *name) {
    state->server_name = strdup(name);
    /* BUG: no NULL check — if strdup fails, strlen crashes */
    printf("Server '%s' initialized (name len: %lu)\n",
           state->server_name, strlen(state->server_name));
    state->log_head = NULL;
    state->active_connections = 0;
    state->total_requests = 0;
    pthread_mutex_init(&state->stats_lock, NULL);
}

/* ──────────────── Main ──────────────── */
int main(void) {
    printf("=== MemGuard Server Simulation ===\n\n");

    /* Init server */
    init_server(&g_server, "memguard-test-v1");

    /* Parse a request (triggers buffer overflow on long methods) */
    HttpRequest *req = parse_request("GET /api/users HTTP/1.1");
    if (req) {
        /* Log it (triggers UAF) */
        log_request(&g_server, req);

        /* Process body (triggers leak on error path) */
        process_body(req, "user=admin&pass=secret");

        /* Handle + free (first free) */
        handle_and_free(req);

        /* BUG 3: double free — req already freed above */
        /* free_request(req); — uncomment to trigger double-free */
    }

    /* Config reading (triggers FD leak) */
    FILE *tmp = fopen("/tmp/mg_test_config.txt", "w");
    if (tmp) {
        fprintf(tmp, "port=8080\nerror=simulated\nhost=localhost\n");
        fclose(tmp);
    }
    read_config("/tmp/mg_test_config.txt");

    /* Thread race simulation */
    pthread_t threads[4];
    int ids[4] = {0, 1, 2, 3};
    for (int i = 0; i < 4; i++) {
        pthread_create(&threads[i], NULL, worker_thread, &ids[i]);
    }
    for (int i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
    }

    /* Log accumulation (leak) */
    for (int i = 0; i < 100; i++) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Request #%d processed", i);
        add_log(&g_server, buf);
    }

    /* Build a response (stack overflow risk) */
    char response[1024];
    build_response("Hello from MemGuard!", response, sizeof(response));
    printf("\nResponse:\n%s\n", response);

    printf("\nStats: %d connections, %d requests\n",
           g_server.active_connections, g_server.total_requests);

    /* BUG: server_name and all log entries leaked */
    printf("Done.\n");
    return 0;
}
