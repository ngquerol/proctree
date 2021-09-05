#include "proctree.h"

/*
 * pstree lookalike
 *
 * TODO:
 * - show only procs belonging to `username`
 * - compress child processes
 * - limit printing to n levels
 * - filtering / options
 * - remove need for sudo in order to see root procs args
 */

/* Environment */

static size_t argmax = 4096;  // default value

static void _set_argmax(void) {
  int mib[2] = {CTL_KERN, KERN_ARGMAX};
  size_t bufsize = sizeof argmax;

  if (sysctl(mib, 2, &argmax, &bufsize, NULL, 0) < 0) {
#if DEBUG
    perror("sysctl");
#endif
  }
}

static size_t maxproc = 2048;  // default value

static void _set_maxproc(void) {
  int mib[2] = {CTL_KERN, KERN_MAXPROC};
  size_t bufsize = sizeof maxproc;

  if (sysctl(mib, 2, &maxproc, &bufsize, NULL, 0) < 0) {
#if DEBUG
    perror("sysctl");
#endif
  }
}

static size_t columns = 0;  // default value (no truncation)

static void _set_columns(void) {
  struct ttysize ttysize;

  if (ioctl(fileno(stdout), TIOCGSIZE, &ttysize) < 0) {
#if DEBUG
    perror("ioctl");
#endif
  }

  columns = ttysize.ts_cols;
}

/* Process info */

static int _get_args(pid_t pid, char *args, size_t args_size) {
  if (!args) return -1;

  // retrieve the process' argc & argv (and env)

  size_t bufsize = args_size;
  char procargs[bufsize];

  int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};

  if (sysctl(mib, 3, procargs, &bufsize, NULL, 0) < 0) {
#if DEBUG
    perror("sysctl");
#endif
    return -1;
  }

  // retrieve process argc

  int argc = *((int *)procargs);

  // bail out if there is no arguments except argv[0]

  if (argc < 2) return 0;

  char *p = procargs + sizeof argc;

  // skip over argv[0]

  for (; p < &procargs[bufsize] && *p; p++) {}

  // skip over trailing (alignment) NUL bytes

  for (; p < &procargs[bufsize] && !*p; p++) {}

  // skip over repeated argv[0]

  for (; p < &procargs[bufsize] && *p; p++) {}

  // by now we should have arrived at argv[1];
  // if not, bail out.

  if (p == &procargs[bufsize]) return 0;

  // iterate through the NUL-separated argument strings,
  // replacing every NUL with a space until we have all
  // our arguments (i == argc - 1, ignoring argv[0])

  char *args_start = p + 1;

  for (int i = 0; i < (argc - 1) && p < &procargs[bufsize]; p++) {
    if (!*p) {
      i++;
      *p = ' ';
    }
  }

  return stpcpy(args, args_start) - args_start;
}

#define USERS_CACHE_MAX_LEN 128
#define USER_NAME_MAX_LEN 32

static struct {
  uid_t uid;
  char name[USER_NAME_MAX_LEN];
} user_cache[USERS_CACHE_MAX_LEN];

static uint8_t user_cache_len = 0;

static void _get_user(uid_t uid, char *name, size_t name_size) {
  uint8_t i = 0;

  // look for uid in cache
  while (i < user_cache_len && user_cache[i].uid != uid) i++;

  // uid not found; retrieve name and update cache
  if (i == user_cache_len) {
    struct passwd *pwd = NULL;

    if ((pwd = getpwuid(uid))) {
      user_cache[i].uid = uid;
      strncpy(user_cache[i].name, pwd->pw_name, sizeof user_cache[0].name);
      user_cache_len++;
    } else {
#if DEBUG
      perror("getpwuid");
#endif
      snprintf(name, name_size, "%d", uid);
      return;
    }
  }

  strncpy(name, user_cache[i].name, name_size);
}

/* Process tree */

#define COMM_LEN ((size_t)17)

// k-ary tree, left-child right-sibling representation
struct proc_node {
  pid_t pid;
  pid_t ppid;
  pid_t pgid;
  uid_t uid;
  char comm[COMM_LEN];
  struct proc_node *first_child;
  struct proc_node *next_sibling;
};

static proc_node_t *_create_node(
    pid_t pid, pid_t ppid, pid_t pgid, uid_t uid, char const *comm) {
  proc_node_t *node;

  if (!(node = malloc(sizeof *node))) {
#if DEBUG
    perror("malloc");
#endif
    return NULL;
  }

  node->pid = pid;
  node->ppid = ppid;
  node->pgid = pgid;
  node->uid = uid;
  snprintf(node->comm, COMM_LEN, "%s", comm);

  node->first_child = NULL;
  node->next_sibling = NULL;

  return node;
}

static struct {
  const char *ancestor;
  const char *leaf;
  const char *leader;
  const char *parent;
  const char *last_child;
  const char *child;
} const indent_chars[] = {{"|", "-", "=", "-", "\\", "|"},  // ASCII
                          {"│", "─", "╼", "─", "╰", "├"}};  // Unicode

static size_t _print_node(proc_node_t const *node,
                          size_t level,
                          char *line,
                          size_t bufsize) {
  // process user
  char user[USER_NAME_MAX_LEN];
  _get_user(node->uid, user, sizeof user);

  // process executable path
  char path[PROC_PIDPATHINFO_MAXSIZE];

  if (proc_pidpath(node->pid, path, PROC_PIDPATHINFO_MAXSIZE) <= 0) {
#if DEBUG
    perror("proc_pidpath");
#endif
    snprintf(path, COMM_LEN, "%s", node->comm);
  }

  // process arguments
  char args[argmax];
  int args_len = _get_args(node->pid, args, sizeof args);

  // tree chars, followed by all of the above
  size_t len = 0;

  if (level) {
    len += snprintf(
        line + len,
        bufsize - len,
        "%s",
        node->next_sibling ? indent_chars->child : indent_chars->last_child);

    len += snprintf(
        line + len,
        bufsize - len,
        "%s%s ",
        node->first_child ? indent_chars->parent : indent_chars->leaf,
        node->pid == node->pgid ? indent_chars->leader : indent_chars->leaf);
  }

  len += snprintf(line + len,
                  bufsize - len,
                  "%05d %s %s %s",
                  node->pid,
                  user,
                  path,
                  args_len > 0 ? args : "");

  return len;
}

static const size_t line_max_len = 8192;

static void _print_tree(proc_node_t const *node,
                        size_t level,
                        const char *indent) {
  if (!node) return;

  // current indent and node
  char line[columns ? columns + 1 : line_max_len];
  size_t indent_len = snprintf(line, sizeof line, "%s", indent);
  _print_node(node, level, line + indent_len, sizeof line - indent_len);

  // truncate line to term width if necessary
  if (columns) {
    line[columns - 3] = '.';
    line[columns - 2] = '.';
    line[columns - 1] = '.';
    line[columns] = '\0';
  }

  puts(line);

  if (!node->first_child) return;

  // children indent, concatenated to existing indent
  snprintf(line + indent_len,
           sizeof line - indent_len,
           "%s%s",
           node->next_sibling ? indent_chars->ancestor : "",
           level ? (node->next_sibling ? "   " : "    ") : "");

  for (proc_node_t *child = node->first_child; child;
       child = child->next_sibling)
    _print_tree(child, level + 1, line);
}

static proc_node_t *_tree_add_child(proc_node_t *parent, proc_node_t *child) {
  if (!parent) return NULL;

  proc_node_t **new_child = &(parent->first_child);

  while (*new_child) new_child = &((*new_child)->next_sibling);

  *new_child = child;

  return *new_child;
}

// could be made iterative with a parent pointer in each node,
// or a stack (but that would be overkill for a process tree)
static proc_node_t *_tree_dfs(proc_node_t *root, pid_t pid) {
  if (!root || root->pid == pid) return root;

  proc_node_t *node = _tree_dfs(root->first_child, pid);

  if (node) return node;

  return _tree_dfs(root->next_sibling, pid);
}

static int _proc_comp(void const *a, void const *b) {
  struct kinfo_proc *p1 = (struct kinfo_proc *)a;
  struct kinfo_proc *p2 = (struct kinfo_proc *)b;

  return p1->kp_proc.p_pid - p2->kp_proc.p_pid;
}

static size_t _list_pids(pid_t root_pid, struct kinfo_proc **procs) {
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, root_pid};
  int miblen = 4;
  size_t bufsize = 0;

  if (sysctl(mib, miblen, NULL, &bufsize, NULL, 0) < 0) {
#if DEBUG
    perror("sysctl");
#endif
    return -1;
  }

  if (!(*procs = malloc(bufsize))) {
#if DEBUG
    perror("malloc");
#endif
    return -1;
  }

  if (sysctl(mib, miblen, *procs, &bufsize, NULL, 0) < 0) {
#if DEBUG
    perror("sysctl");
#endif
    return -1;
  }

  size_t proc_count = bufsize / sizeof(*procs)[0];

  qsort(*procs, proc_count, sizeof(*procs)[0], _proc_comp);

  return proc_count;
}

/* Public API */

proc_node_t *proc_tree_create(pid_t root_pid) {
  struct kinfo_proc *procs;
  int proc_count = 0;

  if ((proc_count = _list_pids(root_pid, &procs)) < 0) return NULL;

  proc_node_t *root = NULL;

  for (int i = 0; i < proc_count; i++) {
    pid_t pid = procs[i].kp_proc.p_pid;
    pid_t ppid = procs[i].kp_eproc.e_ppid;
    pid_t pgid = procs[i].kp_eproc.e_pgid;
    uid_t uid = procs[i].kp_eproc.e_ucred.cr_uid;
    char const *comm = procs[i].kp_proc.p_comm;

    if (root_pid == pid) {
      root = _create_node(pid, ppid, pgid, uid, comm);
      break;
    }
  }

  if (!root) return NULL;  // root PID not found; cannot build tree

  for (int i = 0; i < proc_count; i++) {
    pid_t pid = procs[i].kp_proc.p_pid;

    if (root_pid == pid) continue;

    pid_t ppid = procs[i].kp_eproc.e_ppid;
    pid_t pgid = procs[i].kp_eproc.e_pgid;
    uid_t uid = procs[i].kp_eproc.e_ucred.cr_uid;
    char const *comm = procs[i].kp_proc.p_comm;

    proc_node_t *parent = _tree_dfs(root, ppid);

    if (parent)
      _tree_add_child(parent, _create_node(pid, ppid, pgid, uid, comm));
  }

  free(procs);

  return root;
}

void proc_tree_destroy(proc_node_t **node) {
  if (!node || !*node) return;

  // post-order traversal

  proc_tree_destroy(&(*node)->first_child);
  proc_tree_destroy(&(*node)->next_sibling);

  free(*node);

  *node = NULL;
}

void proc_tree_print(proc_node_t const *node) { _print_tree(node, 0, ""); }

/* Entry point */

static void _print_usage(char const *argv0) {
  fprintf(stdout, "Usage: %s <PID>\n", argv0);
}

static const int max_pid = 99999;

int main(int argc, char *argv[]) {
  if (argc > 2) {
    _print_usage(argv[0]);
    return EXIT_FAILURE;
  }

  pid_t pid = 0;

  if (argc == 2) {
    char *end;
    pid = strtol(argv[1], &end, 10);

    // FIXME: maximum PID value is platform-dependent
    if (*end || pid < 0 || pid >= max_pid) {
      fprintf(stdout, "\"%s\" is not a valid PID.\n", argv[1]);
      _print_usage(argv[0]);
      return EXIT_FAILURE;
    }
  }

  _set_argmax();
  _set_maxproc();

  proc_node_t *proc_tree;

  if (!(proc_tree = proc_tree_create(pid))) {
    printf("Failed to get info of (nonexistent?) process %d.\n", pid);
    return EXIT_FAILURE;
  }

  _set_columns();
  proc_tree_print(proc_tree);
  proc_tree_destroy(&proc_tree);

  return EXIT_SUCCESS;
}
