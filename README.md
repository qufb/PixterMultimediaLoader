# Mattel Pixter Multimedia Loader

Adds LH79524 memory maps and loads game carts along with chip-on-board ROMs.

Note that code execution happens at remap bank (address `0`), after boot mappings were applied. It is mapped to SDRAM (address `0x20000000`), initialized with CS1 ROM (address `0x44000000`). Some hot patching also occurs in SDRAM (e.g. IRQ handler is replaced), which is why the loader asks for both SDRAM and CS1 dumps.
