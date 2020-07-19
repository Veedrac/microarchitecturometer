import sys
from itertools import count, cycle, islice



# Size config
loops = 10000
repeats = 10
test_sizes = range(0, 400, 2)

max_memory = 64 * 1024 * 1024
list_len = max_memory // 8 // repeats // 2

# Test configs
repeat = lambda n, instrs: "".join(islice(cycle(instrs), n))
asm = 'asm volatile(""{} : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4), "+r"(r5), "+r"(list_0), "+r"(list_1) :: "cc");'.format
work_loop = 1024



work_opts = {
    # Generally you want to use the first of these, but the others can potentially be more consistent
    "mem":           "list_{0} = (void **)*list_{0};",
    "hash":          { "padding": "list_{0} = (void **)((size_t)*list_{0} ^ 1000);", "hash_mem": "mem[i] = (void **)((size_t)mem[i] ^ 1000);" },
    "lzcnt-x86":     asm('"lzcnt %{0}, %{0}\\n"' * work_loop),
    "smulh-aarch64": asm('"smulh %{0}, %{0}, %{0}\\n"' * work_loop),
    "clz-aarch64":   asm('"clz %{0}, %{0}\\n"' * work_loop),

    # Singular variant, shows multiple discontinuities to allow more deductive calculations
    # Set repeats much higher than usual (eg. 100) to increase visibility, though loops can be lower
    "parmem": { "work": "r0 += *(size_t *)((size_t)list_0[i * 197] ^ 1000);", "hash_mem": "mem[i] = (void **)((size_t)mem[i] ^ 1000);", "singular": True },
}

padding_opts = {
    # Test for ROB size
    "nop": lambda i: asm('"nop\\n"' * i),

    # Test for NOP collapsing; this can hit other resource limits, so don't expect perfect results. Tuned empirically.
    "generic-x86":     lambda i: asm(repeat(i, ('"test %0, %0\\n"', '"add %1, %1\\n"', '"add %2, %2\\n"', '"jo .+0xF0\\n"', '"test %3, %3\\n"', '"add %4, %4\\n"', '"jo .+0xF0\\n"'))),
    "generic-aarch64": lambda i: asm(repeat(i, ('"cmp %0, %0\\n"', '"add %1, %1, %1\\n"', '"add %2, %2, %2\\n"', '"b.ne .+0xF0\\n"', '"cmp %3, %3\\n"', '"add %4, %4, %4\\n"', '"b.ne .+0xF0\\n"'))),

    # Tests for the number of possible outstanding branches; I'm not sure what this is actually measuring, but it's useful to know
    "branch-x86":     lambda i: asm('"test %2, %2\\n"' + '"jc .+0xF0\\n"' * i),
    "branch-aarch64": lambda i: asm('"cmp %2, %2\\n"' + '"b.ne .+0xF0\\n"' * i),

    # Tests for the number of rename registers — not exact for some reason
    "mov":         lambda i: asm(repeat(i, map('"mov %{0}, %{0}\\n"'.format, range(6)))),
    "cmp":         lambda i: asm(repeat(i, map('"cmp %{0}, %{0}\\n"'.format, range(6)))),
    "add-x86":     lambda i: asm(repeat(i, map('"add %{0}, %{0}\\n"'.format, range(6)))),
    "add-aarch64": lambda i: asm(repeat(i, map('"add %{0}, %{0}, %{0}\\n"'.format, range(6)))),

    # Test for load buffer size
    "load-x86":     { "padding": lambda i: asm(repeat(i, map('"mov (%{0}), %{0}\\n"'.format, range(6)))), "init": "*mem" },
    "load-aarch64": { "padding": lambda i: asm(repeat(i, map('"ldr %{0}, [%{0}]\\n"'.format, range(6)))), "init": "*mem" },

    # Test for store buffer size
    "store-x86":     { "padding": lambda i: asm(repeat(i, map('"mov %0, {}(%0)\\n"'.format,   count(0, 8)))), "init": "*mem", "store_buffer_size": max(test_sizes) },
    "store-aarch64": { "padding": lambda i: asm(repeat(i, map('"str %0, [%0, {}]\\n"'.format, count(0, 8)))), "init": "*mem", "store_buffer_size": max(test_sizes) },
}



try:
    _, work_arg, padding_arg = sys.argv
except ValueError:
    print("microarchitecturometer_generator.py <work> <padding>", file=sys.stderr)
    print("Invalid number of parameters.", file=sys.stderr)
    raise SystemExit

try:
    work_choice = work_opts[work_arg]
except KeyError:
    print(f"Invalid work option {work_arg!r}", file=sys.stderr)
    print("Valid options:", file=sys.stderr)
    for key in work_opts:
        print(f"    {key}", file=sys.stderr)
    raise SystemExit

try:
    padding_choice = padding_opts[padding_arg]
except KeyError:
    print(f"Invalid padding option {padding_arg!r}", file=sys.stderr)
    print("Valid options:", file=sys.stderr)
    for key in padding_opts:
        print(f"    {key}", file=sys.stderr)
    raise SystemExit

if not isinstance(work_choice, dict):
    work_choice = { "work": work_choice }
if not isinstance(padding_choice, dict):
    padding_choice = { "padding": padding_choice }

work = work_choice["work"]
hash_mem = work_choice.get("hash_mem", "")
singular = work_choice.get("singular", False)

padding = padding_choice["padding"]
init = padding_choice.get("init", "0")
store_buffer_size = padding_choice.get("store_buffer_size", 1)



setup = """\
#include <inttypes.h>
#include <memory.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

__attribute__((noinline))
uint64_t get_nanos() {{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
}}


// *Really* minimal PCG32 code / (c) 2014 M.E. O'Neill / pcg-random.org
// Licensed under Apache License 2.0 (NO WARRANTY, etc. see website)
typedef struct {{ uint64_t state;  uint64_t inc; }} pcg32_random_t;

uint32_t pcg32_random_r(pcg32_random_t* rng) {{
    uint64_t oldstate = rng->state;
    rng->state = oldstate * 6364136223846793005ULL + (rng->inc|1);
    uint32_t xorshifted = ((oldstate >> 18u) ^ oldstate) >> 27u;
    uint32_t rot = oldstate >> 59u;
    return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}}

// Creates n_lists linked lists of length list_len,
// such that every n_lists'th element of mem is a member of a given list
void init_memory(void **mem, uint32_t list_len, uint32_t n_lists) {{
    if (!list_len) {{
        return;
    }}

    pcg32_random_t rng = {{0, 0}};
    for (uint32_t i = 0; i < n_lists; ++i) {{
        mem[i] = &mem[i];
    }}
    for (uint32_t i = 1; i < list_len; ++i) {{
        for (uint32_t j = 0; j < n_lists; ++j) {{
            uint32_t k = pcg32_random_r(&rng) % i;
            mem[i * n_lists + j] = mem[k * n_lists + j];
            mem[k * n_lists + j] = &mem[i * n_lists + j];
        }}
    }}

    for (uint32_t i = 0; i < list_len * n_lists; ++i) {{
        {hash_mem}
    }}
}}
"""

time_rob = """
__attribute__((noinline))
uint64_t time_rob_{variant}{n:06}(void **list_0, void **list_1) {{
    uint64_t start = get_nanos();

    uint64_t mem[{store_buffer_size}]; *mem = (uint64_t)mem;
    uint64_t r0 = {init}, r1 = {init}, r2 = {init}, r3 = {init}, r4 = {init}, r5 = {init};
    _Pragma("nounroll")
    for (uint64_t i = 0; i < {loops}; ++i) {{
        {work_0}
        {padding_0}
        {work_1}
        {padding_1}
    }}

    return get_nanos() - start;
}}
"""

main = """\
int main() {{
    void **mem = calloc({list_len} * {repeats} * 2, sizeof(void *));
    init_memory(mem, {list_len}, {repeats} * 2);

    uint64_t results[{n_results}] = {{0}};
    uint64_t results_baseline[{n_results}] = {{0}};

    for (uint32_t i = 0; i < {repeats}; ++i) {{
{run_tests}
    }}

    for (uint32_t i = 0; i < {repeats}; ++i) {{
{run_baseline_tests}
    }}

    printf("padding\ttime taken\ttime taken (baseline)\\n");
{print_results}
}}
"""




print(setup.format(hash_mem=hash_mem))

if singular:
    for size in test_sizes:
        print(time_rob.format(n=size, init=init, store_buffer_size=store_buffer_size, loops=loops, variant="",          work_0=work, work_1="", padding_0=padding(size), padding_1=""))
else:
    for size in test_sizes:
        print(time_rob.format(n=size, init=init, store_buffer_size=store_buffer_size, loops=loops, variant="",          work_0=work.format(0), work_1=work.format(1), padding_0=padding(size), padding_1=padding(size)))
        print(time_rob.format(n=size, init=init, store_buffer_size=store_buffer_size, loops=loops, variant="baseline_", work_0=work.format(0), work_1=work.format(0), padding_0=padding(size), padding_1=padding(size)))

run_tests = "".join(f"""\
        results[{idx}] += time_rob_{size:06}(mem + {2 * idx}, mem + {2 * idx + 1});
""" for idx, size in enumerate(test_sizes))

run_baseline_tests = "".join(f"""\
        results_baseline[{idx}] += time_rob_baseline_{size:06}(mem + {idx}, mem + {2 * idx + 1});
""" for idx, size in enumerate(test_sizes))

print_results = "".join(f"""\
    printf("{size}\t%" PRIu64 "\t%" PRIu64 "\\n", results[{idx}] / {repeats}, results_baseline[{idx}] / {repeats});
""" for idx, size in enumerate(test_sizes))

if singular:
    run_baseline_tests = ""

    print_results = "".join(f"""\
    printf("{size}\t%" PRIu64 "\\n", results[{idx}] / {repeats});
""" for idx, size in enumerate(test_sizes))

print(main.format(n_results=len(test_sizes), list_len=list_len, repeats=repeats, run_tests=run_tests, run_baseline_tests=run_baseline_tests, print_results=print_results))
