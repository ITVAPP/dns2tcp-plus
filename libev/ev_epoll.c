#include <sys/epoll.h>

#define EV_EMASK_EPERM 0x80

static void
epoll_modify (EV_P_ int fd, int oev, int nev)
{
  struct epoll_event ev;
  unsigned char oldmask;

  /*
   * we handle EPOLL_CTL_DEL by ignoring it here
   * on the assumption that the fd is gone anyways
   * if that is wrong, we have to handle the spurious
   * event in epoll_poll.
   * if the fd is added again, we try to ADD it, and, if that
   * fails, we assume it still has the same eventmask.
   */
  if (!nev)
    return;

  oldmask = anfds [fd].emask;
  anfds [fd].emask = nev;

  /* store the generation counter in the upper 32 bits, the fd in the lower 32 bits */
  ev.data.u64 = (uint64_t)(uint32_t)fd
              | ((uint64_t)(uint32_t)++anfds [fd].egen << 32);
  ev.events   = (nev & EV_READ  ? EPOLLIN  : 0)
              | (nev & EV_WRITE ? EPOLLOUT : 0);

  if (ecb_expect_true (!epoll_ctl (backend_fd, oev && oldmask != nev ? EPOLL_CTL_MOD : EPOLL_CTL_ADD, fd, &ev)))
    return;

  if (ecb_expect_true (errno == ENOENT))
    {
      /* if ENOENT then the fd went away, so try to do the right thing */
      if (!nev)
        goto dec_egen;

      if (!epoll_ctl (backend_fd, EPOLL_CTL_ADD, fd, &ev))
        return;
    }
  else if (ecb_expect_true (errno == EEXIST))
    {
      /* EEXIST means we ignored a previous DEL, but the fd is still active */
      /* if the kernel mask is the same as the new mask, we assume it hasn't changed */
      if (oldmask == nev)
        goto dec_egen;

      if (!epoll_ctl (backend_fd, EPOLL_CTL_MOD, fd, &ev))
        return;
    }
  else if (ecb_expect_true (errno == EPERM))
    {
      /* EPERM means the fd is always ready, but epoll is too snobbish */
      /* to handle it, unlike select or poll. */
      anfds [fd].emask = EV_EMASK_EPERM;

      /* add fd to epoll_eperms, if not already inside */
      if (!(oldmask & EV_EMASK_EPERM))
        {
          array_needsize (int, epoll_eperms, epoll_epermmax, epoll_epermcnt + 1, array_needsize_noinit);
          epoll_eperms [epoll_epermcnt++] = fd;
        }

      return;
    }
  else
    assert (("libev: I/O watcher with invalid fd found in epoll_ctl", errno != EBADF && errno != ELOOP && errno != EINVAL));

  fd_kill (EV_A_ fd);

dec_egen:
  /* we didn't successfully call epoll_ctl, so decrement the generation counter again */
  --anfds [fd].egen;
}

static void
epoll_poll (EV_P_ ev_tstamp timeout)
{
  int i;
  int eventcnt;

  if (ecb_expect_false (epoll_epermcnt))
    timeout = EV_TS_CONST (0.);

  /* epoll wait times cannot be larger than (LONG_MAX - 999UL) / HZ msecs, which is below */
  /* the default libev max wait time, however. */
  EV_RELEASE_CB;
  eventcnt = epoll_wait (backend_fd, epoll_events, epoll_eventmax, EV_TS_TO_MSEC (timeout));
  EV_ACQUIRE_CB;

  if (ecb_expect_false (eventcnt < 0))
    {
      if (errno != EINTR)
        ev_syserr ("(libev) epoll_wait");

      return;
    }

  for (i = 0; i < eventcnt; ++i)
    {
      struct epoll_event *ev = epoll_events + i;

      int fd = (uint32_t)ev->data.u64; /* mask out the lower 32 bits */
      int want = anfds [fd].events;
      int got  = (ev->events & (EPOLLOUT | EPOLLERR | EPOLLHUP) ? EV_WRITE : 0)
               | (ev->events & (EPOLLIN  | EPOLLERR | EPOLLHUP) ? EV_READ  : 0);

      /*
       * check for spurious notification.
       * this only finds spurious notifications on egen updates
       * other spurious notifications will be found by epoll_ctl, below
       * we assume that fd is always in range, as we never shrink the anfds array
       */
      if (ecb_expect_false ((uint32_t)anfds [fd].egen != (uint32_t)(ev->data.u64 >> 32)))
        {
          /* recreate kernel state */
          postfork |= 2;
          continue;
        }

      if (ecb_expect_false (got & ~want))
        {
          anfds [fd].emask = want;

          /*
           * we received an event but are not interested in it, try mod or del
           * this often happens because we optimistically do not unregister fds
           * when we are no longer interested in them, but also when we get spurious
           * notifications for fds from another process. this is partially handled
           * above with the gencounter check (== our fd is not the event fd), and
           * partially here, when epoll_ctl returns an error (== a child has the fd
           * but we closed it).
           * note: for events such as POLLHUP, where we can't know whether it refers
           * to EV_READ or EV_WRITE, we might issue redundant EPOLL_CTL_MOD calls.
           */
          ev->events = (want & EV_READ  ? EPOLLIN  : 0)
                     | (want & EV_WRITE ? EPOLLOUT : 0);

          /* pre-2.6.9 kernels require a non-null pointer with EPOLL_CTL_DEL, */
          /* which is fortunately easy to do for us. */
          if (epoll_ctl (backend_fd, want ? EPOLL_CTL_MOD : EPOLL_CTL_DEL, fd, ev))
            {
              postfork |= 2; /* an error occurred, recreate kernel state */
              continue;
            }
        }

      fd_event (EV_A_ fd, got);
    }

  /* if the receive array was full, increase its size */
  if (ecb_expect_false (eventcnt == epoll_eventmax))
    {
      ev_free (epoll_events);
      epoll_eventmax = array_nextsize (sizeof (struct epoll_event), epoll_eventmax, epoll_eventmax + 1);
      epoll_events = (struct epoll_event *)ev_malloc (sizeof (struct epoll_event) * epoll_eventmax);
    }

  /* now synthesize events for all fds where epoll fails, while select works... */
  for (i = epoll_epermcnt; i--; )
    {
      int fd = epoll_eperms [i];
      unsigned char events = anfds [fd].events & (EV_READ | EV_WRITE);

      if (anfds [fd].emask & EV_EMASK_EPERM && events)
        fd_event (EV_A_ fd, events);
      else
        {
          epoll_eperms [i] = epoll_eperms [--epoll_epermcnt];
          anfds [fd].emask = 0;
        }
    }
}

static int
epoll_epoll_create (void)
{
  int fd;

#if defined EPOLL_CLOEXEC && !defined __ANDROID__
  fd = epoll_create1 (EPOLL_CLOEXEC);

  if (fd < 0 && (errno == EINVAL || errno == ENOSYS))
#endif
    {
      fd = epoll_create (256);

      if (fd >= 0)
        fcntl (fd, F_SETFD, FD_CLOEXEC);
    }

  return fd;
}

inline_size
int
epoll_init (EV_P_ int flags)
{
  if ((backend_fd = epoll_epoll_create ()) < 0)
    return 0;

  backend_mintime = EV_TS_CONST (1e-3); /* epoll does sometimes return early, this is just to avoid the worst */
  backend_modify  = epoll_modify;
  backend_poll    = epoll_poll;

  epoll_eventmax = 64; /* initial number of events receivable per poll */
  epoll_events = (struct epoll_event *)ev_malloc (sizeof (struct epoll_event) * epoll_eventmax);

  return EVBACKEND_EPOLL;
}

inline_size
void
epoll_destroy (EV_P)
{
  ev_free (epoll_events);
  array_free (epoll_eperm, EMPTY);
}

ecb_cold
static void
epoll_fork (EV_P)
{
  close (backend_fd);

  while ((backend_fd = epoll_epoll_create ()) < 0)
    ev_syserr ("(libev) epoll_create");

  fd_rearm_all (EV_A);
}

