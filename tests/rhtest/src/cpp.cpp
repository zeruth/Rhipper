/* cpp: C++ as MSVC builds it for x86. __thiscall methods (this in ecx), constructors and
 * destructors, virtual dispatch through vtables, a pure virtual base, virtual destructors called
 * through a base pointer, multiple inheritance (this adjusted for the second base, and the
 * adjustor thunks in its vtable), virtual inheritance (a vbtable), static objects built by the
 * CRT's dynamic initializers (_initterm) and destroyed at exit (atexit), function templates and
 * class templates, operator overloading, references, operator new and delete. No exceptions and
 * no STL: those are programs of their own. */
#include "rhtest.h"

#include <new>

/* a counter of constructions and destructions, by kind, read at the end */
static u32 g_events = 0;
NOINLINE void event(u32 k) { g_events = g_events * 31 + k; }

/* ---- a plain class: members, a constructor, const methods, a static member ---- */
class Counter {
public:
    explicit Counter(int start) : n_(start), steps_(0) { event(1); }
    ~Counter() { event(2); }
    NOINLINE void add(int k) { n_ += k; steps_++; total_ += k; }
    NOINLINE int value() const { return n_ * 10 + steps_; }
    static NOINLINE int total() { return total_; }

private:
    int n_;
    int steps_;
    static int total_;
};
int Counter::total_ = 0;

NOINLINE u32 counters(u32 s) {
    Counter a((int)s), b(-(int)s);
    for (u32 k = 0; k < s; k++) {
        a.add((int)k);
        b.add((int)(k * k));
    }
    return (u32)(a.value() * 1000 + b.value()) ^ (u32)Counter::total();
}

/* ---- virtual dispatch: an abstract base, two derived shapes, a virtual destructor ---- */
class Shape {
public:
    Shape(int id) : id_(id) { event(3); }
    virtual ~Shape() { event(4); }
    virtual int area() const = 0;
    virtual int perimeter() const = 0;
    virtual int kind() const { return 0; }
    int id() const { return id_; }

private:
    int id_;
};

class Rect : public Shape {
public:
    Rect(int id, int w, int h) : Shape(id), w_(w), h_(h) { event(5); }
    ~Rect() override { event(6); }
    int area() const override { return w_ * h_; }
    int perimeter() const override { return 2 * (w_ + h_); }
    int kind() const override { return 1; }

protected:
    int w_, h_;
};

class Square : public Rect {
public:
    Square(int id, int s) : Rect(id, s, s) { event(7); }
    ~Square() override { event(8); }
    int kind() const override { return 2; }
};

class Tri : public Shape {
public:
    Tri(int id, int a, int b, int c) : Shape(id), a_(a), b_(b), c_(c) { event(9); }
    ~Tri() override { event(10); }
    int area() const override { return (a_ * b_) / 2; }      /* (a right triangle's legs) */
    int perimeter() const override { return a_ + b_ + c_; }

private:
    int a_, b_, c_;
};

NOINLINE u32 measure(const Shape &s) { return (u32)(s.area() * 7 + s.perimeter() * 3 + s.kind() * 100 + s.id()); }

NOINLINE u32 shapes(u32 s) {
    Shape *list[4];
    list[0] = new Rect(1, (int)s, (int)s + 2);
    list[1] = new Square(2, (int)s * 2);
    list[2] = new Tri(3, 3 * (int)s, 4 * (int)s, 5 * (int)s);
    list[3] = new Square(4, 1);
    u32 h = 0;
    for (int k = 0; k < 4; k++) h = h * 131 + measure(*list[k]);
    for (int k = 0; k < 4; k++) delete list[k];                /* (through the base: virtual) */
    return h;
}

/* ---- multiple inheritance: the second base's this is adjusted, its vtable thunks back ---- */
struct Named {
    virtual ~Named() {}
    virtual u32 name_hash() const = 0;
    char tag = 'n';
};
struct Valued {
    virtual ~Valued() {}
    virtual int get() const = 0;
    virtual void set(int v) = 0;
    int scale = 3;
};
class Item : public Named, public Valued {
public:
    Item(const char *n, int v) : name_(n), v_(v) { event(11); }
    ~Item() override { event(12); }
    u32 name_hash() const override {
        u32 h = 5381;
        for (const char *p = name_; *p; p++) h = h * 33 + (u8)*p;
        return h;
    }
    int get() const override { return v_ * scale; }
    void set(int v) override { v_ = v; }

private:
    const char *name_;
    int v_;
};

NOINLINE int bump(Valued &v, int k) {
    v.set(v.get() + k);
    return v.get();
}
NOINLINE u32 multi(u32 s) {
    Item *it = new Item("widget", (int)s);
    Valued *v = it;                       /* (this + sizeof(Named)) */
    Named *n = it;
    int r = bump(*v, 5);
    u32 h = n->name_hash() ^ (u32)r ^ (u32)(it->get() << 4);
    delete v;                             /* (the thunk adjusts back to the Item) */
    return h;
}

/* ---- virtual inheritance: one shared base reached through a vbtable ---- */
struct Base0 {
    int b0 = 0;
    virtual int who() const { return 10 + b0; }
    virtual ~Base0() {}
};
struct Left : virtual Base0 {
    int l = 1;
    int who() const override { return 20 + l + b0; }
};
struct Right : virtual Base0 {
    int r = 2;
};
struct Diamond : Left, Right {
    int d = 3;
    int who() const override { return 30 + l + r + d + b0; }
};
NOINLINE int via_base(const Base0 *b) { return b->who(); }
NOINLINE u32 diamond(u32 s) {
    Diamond dm;
    dm.b0 = (int)s;
    Left *lp = &dm;
    Right *rp = &dm;
    rp->r += (int)s;
    return (u32)(via_base(&dm) * 1000 + lp->who() * 10 + rp->b0);
}

/* ---- templates ---- */
template <typename T>
NOINLINE T clamp_t(T v, T lo, T hi) { return v < lo ? lo : (v > hi ? hi : v); }

template <typename T, int N>
class Ring {
public:
    Ring() : head_(0), count_(0) {}
    void push(T v) {
        data_[(head_ + count_) % N] = v;
        if (count_ < N) count_++;
        else head_ = (head_ + 1) % N;
    }
    T sum() const {
        T s = T();
        for (int k = 0; k < count_; k++) s = s + data_[(head_ + k) % N];
        return s;
    }
    int size() const { return count_; }

private:
    T data_[N];
    int head_, count_;
};

/* ---- operator overloading, a value type passed and returned by value ---- */
struct V2 {
    int x, y;
    V2 operator+(const V2 &o) const { return V2{x + o.x, y + o.y}; }
    V2 operator*(int k) const { return V2{x * k, y * k}; }
    bool operator==(const V2 &o) const { return x == o.x && y == o.y; }
    V2 &operator+=(const V2 &o) {
        x += o.x;
        y += o.y;
        return *this;
    }
};
NOINLINE V2 walk(V2 p, int steps) {
    V2 d{1, -2};
    for (int k = 0; k < steps; k++) p += d * (k + 1);
    return p;
}

NOINLINE u32 templates(u32 s) {
    Ring<int, 5> ri;
    Ring<V2, 3> rv;
    for (u32 k = 0; k < s + 4; k++) {
        ri.push((int)(k * k));
        rv.push(V2{(int)k, (int)(s - k)});
    }
    V2 t = rv.sum();
    V2 w = walk(V2{(int)s, 0}, (int)s);
    return (u32)(ri.sum() * 7 + ri.size()) ^ (u32)(t.x * 100 + t.y) ^ (u32)(w.x * 1000 + w.y) ^
           (u32)clamp_t<int>(-(int)s * 9, -20, 20) * 3 ^ (u32)(clamp_t<double>(s * 1.5, 0.0, 9.0) * 10) ^
           (u32)(w == V2{w.x, w.y}) << 30;
}

/* ---- statics: built by the CRT's dynamic initializers before main, torn down at exit ---- */
struct Registry {
    int entries[8];
    int n;
    Registry() : n(0) {
        for (int k = 0; k < 8; k++) entries[k] = k * k + 1;
        event(13);
    }
    ~Registry() { event(14); }
    NOINLINE int sum() const {
        int s = 0;
        for (int k = 0; k < 8; k++) s += entries[k];
        return s + n;
    }
};
static Registry g_registry;
static Counter g_counter(100);

/* ---- references and placement new ---- */
NOINLINE void swap_ref(int &a, int &b) {
    int t = a;
    a = b;
    b = t;
}
NOINLINE u32 refs(u32 s) {
    int a = (int)s, b = (int)s * 3;
    swap_ref(a, b);
    alignas(Counter) unsigned char buf[sizeof(Counter)];
    Counter *c = new (buf) Counter(a);
    c->add(b);
    u32 r = (u32)c->value();
    c->~Counter();
    return r ^ (u32)(a * 100 + b);
}

void rhtest_run(void) {
    u32 s = seed();   /* 7 */
    check("statics", (u32)g_registry.sum() ^ (u32)g_counter.value());
    check("counters", counters(s));
    check("shapes", shapes(s));
    check("multi", multi(s));
    check("diamond", diamond(s));
    check("templates", templates(s));
    check("refs", refs(s));
    check("events", g_events);
}
