#ifndef KVM_EXIT_H_
#define KVM_EXIT_H_

struct kvm_exit_event
{
    int pid;
    int cpu_id;
    int exit_reason;
};

#endif /* KVM_EXIT_H_ */