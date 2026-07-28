struct Receiver;
struct MethodInfo;

struct ShortSlot {
    float (*methodPtr)(struct Receiver *receiver, const struct MethodInfo *method);
    const struct MethodInfo *method;
};

struct VeryLongConcreteGenericOwnerName_VTableSlot {
    float (*methodPtr)(struct Receiver *receiver, const struct MethodInfo *method);
    const struct MethodInfo *method;
};
