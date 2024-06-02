/*
 * Copyright (c) 2015 PLUMgrid, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/syscall.h>
#include <sys/ioctl.h>

#include <fcntl.h>
#include <linux/perf_event.h>


#define PATH_MAX 4096

#define DEBUGFS_TRACEFS "/sys/kernel/debug/tracing"
#define TRACEFS "/sys/kernel/tracing"

int bpf_close_perf_event_fd(int fd) {
  int res, error = 0;
  if (fd >= 0) {
    res = ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    if (res != 0) {
      perror("ioctl(PERF_EVENT_IOC_DISABLE) failed");
      error = res;
    }
    res = close(fd);
    if (res != 0) {
      perror("close perf event FD failed");
      error = (res && !error) ? res : error;
    }
  }
  return error;
}

static const char *get_tracefs_path()
{
  if (access(DEBUGFS_TRACEFS, F_OK) == 0) {
    return DEBUGFS_TRACEFS;
  }
  return TRACEFS;
}

// When a valid Perf Event FD provided through pfd, it will be used to enable
// and attach BPF program to the event, and event_path will be ignored.
// Otherwise, event_path is expected to contain the path to the event in tracefs
// and it will be used to open the Perf Event FD.
// In either case, if the attach partially failed (such as issue with the
// ioctl operations), the **caller** need to clean up the Perf Event FD, either
// provided by the caller or opened here.
static int bpf_attach_tracing_event(int progfd, const char *event_path, int pid,
                                    int *pfd)
{
  int efd, cpu = 0;
  ssize_t bytes;
  char buf[PATH_MAX];
  struct perf_event_attr attr = {};
  // Caller did not provide a valid Perf Event FD. Create one with the tracefs
  // event path provided.
  if (*pfd < 0) {
    snprintf(buf, sizeof(buf), "%s/id", event_path);
    efd = open(buf, O_RDONLY, 0);
    if (efd < 0) {
      fprintf(stderr, "open(%s): %s\n", buf, strerror(errno));
      return -1;
    }

    bytes = read(efd, buf, sizeof(buf));
    if (bytes <= 0 || bytes >= sizeof(buf)) {
      fprintf(stderr, "read(%s): %s\n", buf, strerror(errno));
      close(efd);
      return -1;
    }
    close(efd);
    buf[bytes] = '\0';
    attr.config = strtol(buf, NULL, 0);
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    // PID filter is only possible for uprobe events.
    if (pid < 0)
      pid = -1;
    // perf_event_open API doesn't allow both pid and cpu to be -1.
    // So only set it to -1 when PID is not -1.
    // Tracing events do not do CPU filtering in any cases.
    if (pid != -1)
      cpu = -1;
    *pfd = syscall(__NR_perf_event_open, &attr, pid, cpu, -1 /* group_fd */, PERF_FLAG_FD_CLOEXEC);
    if (*pfd < 0) {
      fprintf(stderr, "perf_event_open(%s/id): %s\n", event_path, strerror(errno));
      return -1;
    }
  }

  if (ioctl(*pfd, PERF_EVENT_IOC_SET_BPF, progfd) < 0) {
    perror("ioctl(PERF_EVENT_IOC_SET_BPF)");
    return -1;
  }
  if (ioctl(*pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    perror("ioctl(PERF_EVENT_IOC_ENABLE)");
    return -1;
  }

  return 0;
}

int bpf_attach_tracepoint(int progfd, const char *tp_category,
                          const char *tp_name)
{
  char buf[256];
  int pfd = -1;

  snprintf(buf, sizeof(buf), "%s/events/%s/%s", get_tracefs_path(), tp_category, tp_name);
  if (bpf_attach_tracing_event(progfd, buf, -1 /* PID */, &pfd) == 0)
    return pfd;

  bpf_close_perf_event_fd(pfd);
  return -1;
}

int bpf_detach_tracepoint(const char *tp_category, const char *tp_name) {
  /* UNUSED(tp_category); */
  /* UNUSED(tp_name); */
  // Right now, there is nothing to do, but it's a good idea to encourage
  // callers to detach anything they attach.
  return 0;
}
