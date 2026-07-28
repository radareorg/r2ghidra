struct Receiver;
struct MethodInfo;

struct ShortSlot {
    float (*methodPtr)(struct Receiver *, const struct MethodInfo *);
    const struct MethodInfo *method;
};

struct VeryLongConcreteGenericOwnerName_VTableSlot {
    float (*methodPtr)(struct Receiver *, const struct MethodInfo *);
    const struct MethodInfo *method;
};

float call_short_slot(struct ShortSlot *slot, struct Receiver *receiver)
{
    return slot->methodPtr(receiver, slot->method);
}

float call_long_slot(struct VeryLongConcreteGenericOwnerName_VTableSlot *slot,
                     struct Receiver *receiver)
{
    return slot->methodPtr(receiver, slot->method);
}
