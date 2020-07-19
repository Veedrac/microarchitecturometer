Measures microarchitectural details. Customize microarchitecturometer_generator.py by commenting/uncommenting lines, then run

    python3 microarchitecturometer_generator.py mem nop > microarchitecturometer.c
    clang microarchitecturometer.c -O3 -o microarchitecturometer
    ./microarchitecturometer

Plot the results.
