#pragma once
// Retained native post-exit proof. Enrollment/status never asserts storage flush.
#include "boundary.hpp"
#include <sys/event.h>
namespace arbol_exit {
using arbol_boundary::Identity;
class ExitWatch {
  int queue_=-1; Identity original_{}; bool attempted_=false, enrolled_=false, uncertain_=false, seen_=false;
  int status_=-1; double observed_=0;
public:
  ExitWatch()=default;
  ExitWatch(const ExitWatch&)=delete; ExitWatch& operator=(const ExitWatch&)=delete;
  ~ExitWatch() { if(queue_>=0) close(queue_); }
  bool enroll(const Identity& original) {
    if(attempted_) return false; attempted_=true;
    // SDK macosx27.0 sys/event.h: NOTE_EXITSTATUS is available to a
    // child watcher OR a process allowed to signal the exact target. Enrollment
    // is made by each genuine signed monitor while the original is still live.
    if(original.pid<=1 || original.uid!=geteuid() || arbol_boundary::current(original)!=1) return false;
    queue_=kqueue(); if(queue_<0 || fcntl(queue_,F_SETFD,FD_CLOEXEC)) { uncertain_=true; return false; }
    struct kevent change{},receipt{}; timespec zero{};
    EV_SET(&change,(uintptr_t)original.pid,EVFILT_PROC,EV_ADD|EV_ENABLE|EV_CLEAR|EV_RECEIPT,
      NOTE_EXIT|NOTE_EXITSTATUS,0,this);
    int count=kevent(queue_,&change,1,&receipt,1,&zero);
    constexpr uint16_t receiptFlags=EV_ADD|EV_ENABLE|EV_CLEAR|EV_RECEIPT|EV_ERROR;
    if(count!=1 || receipt.ident!=(uintptr_t)original.pid || receipt.filter!=EVFILT_PROC ||
       !(receipt.flags&EV_ERROR) || (receipt.flags&~receiptFlags) || receipt.fflags!=(NOTE_EXIT|NOTE_EXITSTATUS) ||
       receipt.data!=0 || receipt.udata!=this ||
       arbol_boundary::current(original)!=1) { uncertain_=true; return false; }
    original_=original; enrolled_=true; return true;
  }
  bool enrolledAlive(const Identity& main) const {
    return enrolled_ && !uncertain_ && !seen_ && arbol_boundary::same(main,original_) && arbol_boundary::current(original_)==1;
  }
  bool poll() {
    if(!enrolled_ || uncertain_) return false;
    struct kevent events[2]{}; timespec zero{};
    int count=kevent(queue_,nullptr,0,events,2,&zero);
    if(count<0 || count>1 || (seen_ && count)) { uncertain_=true; return false; }
    if(!count) return true;
    const auto& event=events[0];
    constexpr uint16_t permitted=EV_ADD|EV_ENABLE|EV_CLEAR|EV_ONESHOT|EV_EOF;
    if(event.ident!=(uintptr_t)original_.pid || event.filter!=EVFILT_PROC || event.udata!=this ||
       (event.flags&~permitted) || !(event.flags&EV_EOF) || !(event.flags&EV_ONESHOT) ||
       event.fflags!=(NOTE_EXIT|NOTE_EXITSTATUS) || event.data<0 || event.data>INT_MAX) {
      uncertain_=true; return false;
    }
    seen_=true; status_=(int)event.data; observed_=arbol_boundary::clockMs(); return true;
  }
  // Only a timely actually observed ordinary zero wait status is eligible for
  // the later independent family/flush/peer/final-holder proof. Nothing here
  // resets a deadline, liveness loss, force latch or native admission authority.
  bool ordinaryBefore(double deadline) const {
    return enrolled_ && !uncertain_ && seen_ && observed_<deadline && WIFEXITED(status_) && WEXITSTATUS(status_)==0;
  }
  bool observed() const { return enrolled_ && !uncertain_ && seen_; }
  double observedAt() const { return observed_; }
  int status() const { return status_; }
  const Identity& original() const { return original_; }
};
} // namespace arbol_exit
