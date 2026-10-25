/* float: floating point on x86. The default builds use SSE2 for scalars (/arch:SSE2), the IA32
 * variant the x87 stack; float and double parameters go on the stack and results come back in
 * st0 either way. Conversions to and from 64-bit integers are the CRT's helpers (_ftol2, _dtol3,
 * _ultod3, ...). Every result is printed as its bits, so the port must match to the last one. */
#include <math.h>

#include "rhtest.h"

static u32 fbits(float f) {
    union {
        float f;
        u32 u;
    } x;
    x.f = f;
    return x.u;
}

static u64 dbits(double d) {
    union {
        double d;
        u64 u;
    } x;
    x.d = d;
    return x.u;
}

static void checkf(const char *name, float f) { check(name, fbits(f)); }
static void checkd(const char *name, double d) { check64(name, dbits(d)); }

NOINLINE float fadd3(float a, float b, float c) { return a + b - c; }
NOINLINE float fmuldiv(float a, float b) { return a * b / (a - b); }
NOINLINE double dadd3(double a, double b, double c) { return a + b - c; }
NOINLINE double dmuldiv(double a, double b) { return a * b / (a - b); }
NOINLINE double dmix(float a, double b, int c) { return a * b + c; }     /* float, int widened */
NOINLINE float fneg(float a) { return -a; }
NOINLINE double dabs_(double a) { return fabs(a); }
NOINLINE double dsqrt(double a) { return sqrt(a); }
NOINLINE float fsqrt(float a) { return sqrtf(a); }

/* conversions */
NOINLINE i32 d2i(double a) { return (i32)a; }                         /* truncation */
NOINLINE u32 d2u(double a) { return (u32)a; }
NOINLINE i64 d2l(double a) { return (i64)a; }                         /* _dtol3 */
NOINLINE u64 d2ul(double a) { return (u64)a; }                        /* _dtoul3 */
NOINLINE double i2d(i32 a) { return (double)a; }
NOINLINE double u2d(u32 a) { return (double)a; }
NOINLINE double l2d(i64 a) { return (double)a; }                      /* _ltod3 */
NOINLINE double ul2d(u64 a) { return (double)a; }                     /* _ultod3 */
NOINLINE float d2f(double a) { return (float)a; }
NOINLINE double f2d(float a) { return (double)a; }
NOINLINE i32 f2i(float a) { return (i32)a; }

/* comparisons: ordered, unordered, equal, the NaN cases */
NOINLINE u32 dcmp(double a, double b) {
    return (u32)(a < b) | (u32)(a <= b) << 1 | (u32)(a > b) << 2 | (u32)(a >= b) << 3 | (u32)(a == b) << 4 |
           (u32)(a != b) << 5;
}

NOINLINE u32 fcmp(float a, float b) {
    return (u32)(a < b) | (u32)(a <= b) << 1 | (u32)(a > b) << 2 | (u32)(a >= b) << 3 | (u32)(a == b) << 4 |
           (u32)(a != b) << 5;
}

NOINLINE double dmin(double a, double b) { return a < b ? a : b; }
NOINLINE double dclamp(double v, double lo, double hi) { return v < lo ? lo : v > hi ? hi : v; }

/* loops over doubles: a polynomial (Horner), a series, Newton's square root */
NOINLINE double horner(const double *c, int n, double x) {
    double r = 0.0;
    int k;
    for (k = n - 1; k >= 0; k--) r = r * x + c[k];
    return r;
}

NOINLINE double series(int n) {
    double s = 0.0;
    int k;
    for (k = 1; k <= n; k++) s += (k & 1 ? 1.0 : -1.0) / (2 * k - 1);
    return 4.0 * s;
}

NOINLINE double newton(double a) {
    double x = a > 1.0 ? a : 1.0;
    int k;
    for (k = 0; k < 30; k++) x = 0.5 * (x + a / x);
    return x;
}

NOINLINE float fsum(const float *v, int n) {
    float s = 0.0f;
    int k;
    for (k = 0; k < n; k++) s += v[k] * (float)(k + 1);
    return s;
}

/* a struct of floats, by pointer and by value */
typedef struct {
    float x, y, z;
} Vec3;

NOINLINE float dot(const Vec3 *a, const Vec3 *b) { return a->x * b->x + a->y * b->y + a->z * b->z; }
NOINLINE Vec3 cross(Vec3 a, Vec3 b) {
    Vec3 r;
    r.x = a.y * b.z - a.z * b.y;
    r.y = a.z * b.x - a.x * b.z;
    r.z = a.x * b.y - a.y * b.x;
    return r;
}

NOINLINE u32 vec_check(void) {
    Vec3 a, b, c;
    float s = (float)seed();
    a.x = s; a.y = 2.5f; a.z = -1.25f;
    b.x = 0.5f; b.y = -s; b.z = 3.0f;
    c = cross(a, b);
    return fbits(dot(&a, &c)) ^ fbits(c.x) ^ fbits(c.y) * 3 ^ fbits(c.z) * 5;
}

/* a float zeroed with `xorps xmm0, xmm0` right after an integer call: no read of an xmm0 result.
 * Taken for one after free, it made free and, through every wrapper, the allocators float ones
 * (CrystalCore, 7,136 xmm0 returns) */
static u32 g_calls;
NOINLINE u32 bump(u32 k) { g_calls += k; return g_calls; }
NOINLINE float after_call(u32 n, float step) {
    u32 b = bump(n);
    float acc = 0.0f;
    u32 k;
    for (k = 0; k < n; k++) acc += step * (float)k;
    return acc + (float)b;
}

/* an 8-byte struct returned in edx:eax, an x87 constant loaded before its high half is read:
 * `call pair_of; fld qword ptr [c]; ...; mov [esp + x], edx`. Scanned only up to the x87 load, the
 * callee returned eax alone and the high half was extraout_EDX (VS2010's templates() and walk(),
 * rhtest msvc-16.00-x86 cpp-O2) */
typedef struct { i32 lo, hi; } Pair32;
NOINLINE Pair32 pair_of(u32 s) {
    Pair32 p;
    p.lo = (i32)s * 3;
    p.hi = -(i32)s * 7;
    return p;
}
NOINLINE double pair_scale(u32 s) {
    Pair32 p = pair_of(s);
    double d = (double)s * 0.75;
    return d * 1.5 + (double)p.hi * 0.5 + (double)p.lo;
}

/* globals of float type */
float g_scale = 1.5f;
double g_offset = -0.125;
NOINLINE double scaled(double v) { return v * g_scale + g_offset; }

void rhtest_run(void) {
    double s = (double)seed();           /* 7.0 */
    float sf = (float)seed();
    double zero = s - 7.0;
    double nan = zero / zero;
    double inf = 1.0 / zero;
    double coef[5];
    float fv[6];
    int k;
    checkf("fadd3", fadd3(sf, 0.1f, 2.0f));
    checkf("fmuldiv", fmuldiv(sf, 3.3f));
    checkd("dadd3", dadd3(s, 0.1, 2.0));
    checkd("dmuldiv", dmuldiv(s, 3.3));
    checkd("dmix", dmix(sf * 0.3f, s / 9.0, -(int)s));
    checkf("fneg", fneg(sf));
    checkd("dabs", dabs_(-s * 1.75));
    checkd("dsqrt", dsqrt(s * 3.0));
    checkf("fsqrt", fsqrt(sf * 5.0f));
    check("d2i", (u32)d2i(-s * 1234.567));
    check("d2u", d2u(s * 600000000.0));
    check("d2u_frac", d2u(s * 600000000.0 + 0.75));      /* (truncated: VS2010's fldcw | 0xc00) */
    check64("d2l", (u64)d2l(-s * 1.0e15));
    check64("d2ul", d2ul(s * 2.5e18));
    checkd("i2d", i2d(-(i32)seed() * 100003));
    checkd("u2d", u2d(0xfffffff0u + seed()));
    checkd("l2d", l2d(-(i64)seed() * 0x123456789abll));
    checkd("ul2d", ul2d(0xfffffffffffffff0ull + seed()));
    checkf("d2f", d2f(s / 3.0));
    checkd("f2d", f2d(sf / 3.0f));
    check("f2i", (u32)f2i(-sf * 99.9f));
    check("dcmp_lt", dcmp(s, s + 1.0));
    check("dcmp_eq", dcmp(s, s));
    check("dcmp_nan", dcmp(nan, s));
    check("dcmp_inf", dcmp(inf, s));
    check("fcmp_lt", fcmp(sf, -sf));
    check("fcmp_nan", fcmp((float)nan, sf));
    checkd("dmin", dmin(s, -s));
    checkd("dclamp", dclamp(s * 3.0, -1.0, 10.5) + dclamp(-s, 0.0, 1.0));
    for (k = 0; k < 5; k++) coef[k] = (k - 2) * 0.75 + s;
    checkd("horner", horner(coef, 5, 1.0 / s));
    checkd("series", series((int)s * 100));
    checkd("newton", newton(s * 11.0));
    for (k = 0; k < 6; k++) fv[k] = sf / (float)(k + 2);
    checkf("fsum", fsum(fv, 6));
    check("vec", vec_check());
    checkd("scaled", scaled(s));
    checkf("after_call", after_call((u32)s, sf * 0.25f));
    checkd("pair_scale", pair_scale((u32)s));
}
