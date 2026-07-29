struct Receiver;
struct MethodInfo;

union CallbackSlot {
    float (*fn)(struct Receiver *receiver, const struct MethodInfo *method);
    void *raw;
};

struct UnionSlot {
    union CallbackSlot cb;
    const struct MethodInfo *method;
};
