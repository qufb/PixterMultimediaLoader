/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package loader;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.OptionDialog;
import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.Option;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.AddressLabelInfo;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class PixterMultimediaLoader extends AbstractLibrarySupportLoader {

    private boolean isBootRomLoaded = false;
    private boolean isCS1RomLoaded = false;

    @Override
    public String getName() {
        return "Mattel Pixter Multimedia Loader";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        BinaryReader reader = new BinaryReader(provider, false);

        // Cart magic
        byte[] bytes = reader.readByteArray(0, 0x8);
        Pattern magic = Pattern.compile("\\xcc\\x66\\x55\\xaa\\x01\\x00\\x00\\x00");
        Matcher matcher = magic.matcher(new ByteCharSequence(bytes));
        if (matcher.find()) {
            loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:v4t", "default"), true));
        }

        // Boot ROM interrupt vectors
        bytes = reader.readByteArray(0, 0x20);
        magic = Pattern.compile("\\x0a\\x00\\x00\\xea\\x05\\x00\\x00\\xea\\x05\\x00\\x00\\xea\\x05\\x00\\x00\\xea\\x05\\x00\\x00\\xea\\x00\\x00\\xa0\\xe1\\xf0\\xff\\x1f\\xe5\\x50\\x00\\x00\\xea");
        matcher = magic.matcher(new ByteCharSequence(bytes));
        if (matcher.find()) {
            this.isBootRomLoaded = true;
            loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:v4t", "default"), true));
        }

        // CS1 ROM interrupt vectors
        bytes = reader.readByteArray(0, 0x20);
        magic = Pattern.compile("\\x12\\x00\\x00\\xea\\x05\\x00\\x00\\xea\\x06\\x00\\x00\\xea\\x07\\x00\\x00\\xea\\x08\\x00\\x00\\xea\\x00\\x00\\xa0\\xe1\\xf0\\xff\\x1f\\xe5\\x09\\x00\\x00\\xea");
        matcher = magic.matcher(new ByteCharSequence(bytes));
        if (matcher.find()) {
            this.isCS1RomLoaded = true;
            loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:v4t", "default"), true));
        }

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider,
            LoadSpec loadSpec,
            List<Option> options,
            Program program,
            TaskMonitor monitor,
            MessageLog log) throws CancelledException, IOException {
        BinaryReader reader = new BinaryReader(provider, false);
        FlatProgramAPI fpa = new FlatProgramAPI(program, monitor);

        InputStream providerStream = provider.getInputStream(0);

        InputStream cs2Stream = null;
        if (!this.isBootRomLoaded && !this.isCS1RomLoaded) {
            cs2Stream = providerStream;
        }
        final long cs2Size = Math.min(cs2Stream != null ? cs2Stream.available() : 0, 0x400000L);

        int choice = 0;
        InputStream cs1Stream = null;
        if (!this.isCS1RomLoaded) {
            choice = OptionDialog.showOptionNoCancelDialog(
                null,
                "CS1 mapping",
                "Load CS1 file?",
                "Yes",
                "No (Just create empty mapping)",
                OptionDialog.QUESTION_MESSAGE
            );
            if (choice == OptionDialog.OPTION_ONE) {
                GhidraFileChooser chooser = new GhidraFileChooser(null);
                chooser.setTitle("Open CS1 file");
                File file = chooser.getSelectedFile(true);
                if (file != null) {
                    cs1Stream = new FileInputStream(file);
                }
            }
        } else {
            cs1Stream = providerStream;
        }
        final long cs1Size = Math.min(cs1Stream != null ? cs1Stream.available() : 0, 0x400000L);

        InputStream sdramStream = null;
        if (!this.isBootRomLoaded && !this.isCS1RomLoaded) {
            choice = OptionDialog.showOptionNoCancelDialog(
                null,
                "SDRAM mapping",
                "Load SDRAM file?",
                "Yes",
                "No (Use CS1 file in memory remap bank)",
                OptionDialog.QUESTION_MESSAGE
            );
            if (choice == OptionDialog.OPTION_ONE) {
                GhidraFileChooser chooser = new GhidraFileChooser(null);
                chooser.setTitle("Open SDRAM file");
                File file = chooser.getSelectedFile(true);
                if (file != null) {
                    sdramStream = new FileInputStream(file);
                }
            } else {
                sdramStream = cs1Stream;
            }
        }
        final long sdramSize = Math.min(sdramStream != null ? sdramStream.available() : 0, 0x400000L);

        InputStream bootRomStream = null;
        if (!this.isBootRomLoaded) {
            choice = OptionDialog.showOptionNoCancelDialog(
                null,
                "Boot ROM mapping",
                "Load Boot ROM file?",
                "Yes",
                "No (Just create empty mapping)",
                OptionDialog.QUESTION_MESSAGE
            );
            if (choice == OptionDialog.OPTION_ONE) {
                GhidraFileChooser chooser = new GhidraFileChooser(null);
                chooser.setTitle("Open Boot ROM file");
                File file = chooser.getSelectedFile(true);
                if (file != null) {
                    bootRomStream = new FileInputStream(file);
                }
            }
        } else {
            bootRomStream = providerStream;
        }
        final long bootRomSize = Math.min(bootRomStream != null ? bootRomStream.available() : 0, 0x2000L);

        createSegment(fpa, sdramStream,   "SDRAM",          0x20000000L, sdramSize, true, true, true, true, log);
        createSegment(fpa, null,          "CS0",            0x40000000L, 0x400000L, true, false, true, false, log);
        createSegment(fpa, cs1Stream,     "CS1",            0x44000000L, cs1Size, true, false, true, false, log);
        createSegment(fpa, cs2Stream,     "CS2",            0x48000000L, cs2Size, true, false, true, false, log);
        createSegment(fpa, null,          "CS3",            0x4C000000L, 0x400000L, true, false, true, false, log);
        createSegment(fpa, null,          "INTERNAL_SRAM",  0x60000000L, 0x4000L, true, true, false, true, log);
        createSegment(fpa, bootRomStream, "BOOT_ROM",       0x80000000L, bootRomSize, true, false, true, false, log);
        createSegment(fpa, null,          "APB_BRIDGE",     0xFFFC0000L, 0x27000L, true, true, false, true, log);
        createSegment(fpa, null,          "EXT_MEM_CNTL",   0xFFFF1000L, 0x1000L, true, true, false, true, log);
        createSegment(fpa, null,          "COLOR_LCD_CNTL", 0xFFFF4000L, 0x1000L, true, true, false, true, log);
        createSegment(fpa, null,          "USB_DEVICE",     0xFFFF5000L, 0x1000L, true, true, false, true, log);
        createSegment(fpa, null,          "VEC_INT_CNTL",   0xFFFFF000L, 0x1000L, true, true, false, true, log);

        // 0xFFFE2008 = 01
        long remapAddress = 0x20000000L;
        long remapSize = sdramSize;
        if (this.isBootRomLoaded) {
            // Reset with pin PC6 = 1
            remapAddress = 0x80000000L;
            remapSize = bootRomSize;
        } else if (this.isCS1RomLoaded) {
            remapAddress = 0x44000000L;
            remapSize = cs1Size;
        }
        // Need to overwrite rwx, otherwise decompilation won't label referenced data addresses (?)
        createMirrorSegment(program.getMemory(), fpa, "REMAP_BANK", remapAddress, 0L, remapSize, 0b101, log);

        // Mirrored range should go up to 0x7FFFFFFF, but let's just map the first ones
        for (int i = 0; i < 4; i++) {
            createMirrorSegment(program.getMemory(), fpa, "INTERNAL_SRAM_" + String.format("%02d", i), 0x60000000L, 0x60000000L + ((i + 1) * 0x4000L), 0x4000L, log);
        }

        createNamedArray(fpa, program, 0xFFFC0000L, "UART0", 0x1000, ByteDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFC1000L, "UART1", 0x1000, ByteDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFC2000L, "UART2", 0x1000, ByteDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFC3000L, "ANA_2_DIG_CVTR", 0x1000, ByteDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFC4000L, "TIMER_MOD", 0x1000, ByteDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFC5000L, "I2C", 0x1000, ByteDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFC6000L, "SYNC_SERIAL", 0x1000, ByteDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFC7000L, "ETH", 0x1000, ByteDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFC8000L, "I2S_CVTR", 0x1000, ByteDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFD9000L, "GPIO_M_N", 0x1000, ByteDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFDA000L, "GPIO_K_L", 0x1000, ByteDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFDB000L, "GPIO_I_J", 0x1000, ByteDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFDC000L, "GPIO_G_H", 0x1000, ByteDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFDD000L, "GPIO_E_F", 0x1000, ByteDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFDE000L, "GPIO_C_D", 0x1000, ByteDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFDF000L, "GPIO_A_B", 0x1000, ByteDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFE0000L, "RTC", 0x1000, ByteDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFE1000L, "DMA_CNTL", 0x1000, ByteDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2000L, "RCPC_CNTL", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2004L, "RCPC_CHIPID", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2008L, "RCPC_REMAP", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE200CL, "RCPC_SOFTRESET", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2010L, "RCPC_RSTSTATUS", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2014L, "RCPC_RSTSTATUSCLR", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2018L, "RCPC_SYSCLKPRE", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE201CL, "RCPC_CPUCLKPRE", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2020L, "RCPC_20", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2024L, "RCPC_PCLKCNTL0", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2028L, "RCPC_PCLKCNTL1", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE202CL, "RCPC_AHBCLKCNTL", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2030L, "RCPC_PCLKSEL0", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2034L, "RCPC_PCLKSEL1", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2038L, "RCPC_38", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE203CL, "RCPC_SILICONREV", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2040L, "RCPC_LCDPRE", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2044L, "RCPC_SSPPRE", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2048L, "RCPC_ADCPRE", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE204CL, "RCPC_USBPRE", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2050L, "RCPC_50", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2054L, "RCPC_54", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2058L, "RCPC_58", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE205CL, "RCPC_5C", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2060L, "RCPC_60", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2064L, "RCPC_64", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2068L, "RCPC_68", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE206CL, "RCPC_6C", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2070L, "RCPC_70", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2074L, "RCPC_74", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2078L, "RCPC_78", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE207CL, "RCPC_7C", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2080L, "RCPC_INTCONFIG", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2084L, "RCPC_INTCLR", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE2088L, "RCPC_CORECONFIG", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE208CL, "RCPC_8C", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE20C0L, "RCPC_SYSPLLCNTL", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE20C4L, "RCPC_USBPLLCNTL", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE20C8L, "RCPC_C8", DWordDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFE3000L, "WATCHDOG_TIMER", 0x1000, ByteDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFE4000L, "LCD_ICP", 0x1000, ByteDataType.dataType, log);
        createNamedArray(fpa, program, 0xFFFE5000L, "IO_CONFIG", 0x1000, ByteDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE6000L, "BOOT_CNTL_PBC", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE6004L, "BOOT_CNTL_CS1OV", DWordDataType.dataType, log);
        createNamedData(fpa,  program, 0xFFFE6008L, "BOOT_CNTL_EPM", DWordDataType.dataType, log);

        // ARM interrupt vectors
        for (int i = 0; i < 0x20; i += 4) {
            new ArmDisassembleCommand(fpa.toAddr(i), null, false).applyTo(program);
        }

        // Always use language defined labels, regardless of APPLY_LABELS_OPTION_NAME...
        List<AddressLabelInfo> labels = loadSpec.getLanguageCompilerSpec().getLanguage().getDefaultSymbols();
        for (AddressLabelInfo info : labels) {
            try {
                // ...but only ARM interrupt vectors.
                final long offset = info.getAddress().getUnsignedOffset();
                if (offset > 0x20) {
                    continue;
                }
                program.getSymbolTable().createLabel(info.getAddress(), info.getLabel(), SourceType.IMPORTED);
            } catch (InvalidInputException e) {
                log.appendException(e);
            }
        }

        monitor.setMessage(String.format("%s : Loading done", getName()));
    }

    private void createSegment(FlatProgramAPI fpa,
            InputStream stream,
            String name,
            long address,
            long size,
            boolean read,
            boolean write,
            boolean execute,
            boolean volatil,
            MessageLog log) {
        MemoryBlock block;
        try {
            block = fpa.createMemoryBlock(name, fpa.toAddr(address), stream, size, false);
            block.setRead(read);
            block.setWrite(write);
            block.setExecute(execute);
            block.setVolatile(volatil);
        } catch (Exception e) {
            log.appendException(e);
        }
    }

    private void createNamedData(FlatProgramAPI fpa,
            Program program,
            long address,
            String name,
            DataType type,
            MessageLog log) {
        try {
            if (type.equals(ByteDataType.dataType)) {
                fpa.createByte(fpa.toAddr(address));
            } else if (type.equals(WordDataType.dataType)) {
                fpa.createWord(fpa.toAddr(address));
            } else if (type.equals(DWordDataType.dataType)) {
                fpa.createDWord(fpa.toAddr(address));
            }
            program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
        } catch (Exception e) {
            log.appendException(e);
        }
    }

    private void createNamedArray(FlatProgramAPI fpa,
            Program program,
            long address,
            String name,
            int numElements,
            DataType type,
            MessageLog log) {
        try {
            CreateArrayCmd arrayCmd = new CreateArrayCmd(fpa.toAddr(address), numElements, type, type.getLength());
            arrayCmd.applyTo(program);
            program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
        } catch (InvalidInputException e) {
            log.appendException(e);
        }
    }

    private void createMirrorSegment(Memory memory,
            FlatProgramAPI fpa,
            String name,
            long src,
            long dst,
            long size,
            MessageLog log) {
        MemoryBlock block;
        Address baseAddress = fpa.toAddr(src);
        try {
            block = memory.createByteMappedBlock(name, fpa.toAddr(dst), baseAddress, size, false);

            MemoryBlock baseBlock = memory.getBlock(baseAddress);
            block.setRead(baseBlock.isRead());
            block.setWrite(baseBlock.isWrite());
            block.setExecute(baseBlock.isExecute());
            block.setVolatile(baseBlock.isVolatile());
        } catch (Exception e) {
            log.appendException(e);
        }
    }

    private void createMirrorSegment(Memory memory,
            FlatProgramAPI fpa,
            String name,
            long src,
            long dst,
            long size,
            int rwx,
            MessageLog log) {
        MemoryBlock block;
        Address baseAddress = fpa.toAddr(src);
        try {
            block = memory.createByteMappedBlock(name, fpa.toAddr(dst), baseAddress, size, false);

            MemoryBlock baseBlock = memory.getBlock(baseAddress);
            block.setRead((rwx & 0b100) != 0);
            block.setWrite((rwx & 0b010) != 0);
            block.setExecute((rwx & 0b001) != 0);
            block.setVolatile(baseBlock.isVolatile());
        } catch (Exception e) {
            log.appendException(e);
        }
    }


    public class ByteCharSequence implements CharSequence {

        private final byte[] data;
        private final int length;
        private final int offset;

        public ByteCharSequence(byte[] data) {
            this(data, 0, data.length);
        }

        public ByteCharSequence(byte[] data, int offset, int length) {
            this.data = data;
            this.offset = offset;
            this.length = length;
        }

        @Override
        public int length() {
            return this.length;
        }

        @Override
        public char charAt(int index) {
            return (char) (data[offset + index] & 0xff);
        }

        @Override
        public CharSequence subSequence(int start, int end) {
            return new ByteCharSequence(data, offset + start, end - start);
        }
    }
}
