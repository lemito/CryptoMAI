perf stat -e cycles,instructions,cache-misses,bus-cycles ./your_program

perf c2c record ./your_program
perf c2c report

perf lock record ./your_program
perf lock report

perf record -F 99 -ag -g --call-graph dwarf ./your_program
perf report -g graph
