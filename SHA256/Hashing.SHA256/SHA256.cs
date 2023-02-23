using System.Text;

namespace Hashing.SHA256; 

public partial class SHA256 {

    public SHA256() {
        _blockLength = 512;
        _wordLength = 32;
        _iterationsCount = 64;
    }

    

    public int BlockLength => _blockLength;
    public int WordLength => _wordLength;
    public int IterationsCount => _iterationsCount;
    
    private readonly int _blockLength;
    private readonly int _wordLength;
    private readonly int _iterationsCount;


    
    public String HashMessage(String message) {
        List<Byte> sourceData = new List<Byte>(Encoding.UTF8.GetBytes(message));
        PaddingSourceData(sourceData);

        Block[] blocks = SplitPaddedDataToBlocks(sourceData.ToArray());
        UInt32[] workingVariables = InitializeWorkingVariables();

        for (int blockIndex = 0; blockIndex < blocks.Length; blockIndex++) {
            UInt32[] words = Utils.SplitBlockToWords(blocks[blockIndex]);
            
            CalculateWordsValues(words);
            CalculateHashValues(words, workingVariables);
        }

        return ConvertHashValuesToDigest(workingVariables);
    }

    private void PaddingSourceData(List<Byte> sourceData) {
        int sourceLength = sourceData.Count * 8;
        int paddingLength = CalculatePaddingLength(sourceLength);
        
        sourceData.Add(0x80);
        for(int i = 0; i < paddingLength; i += 8)
            sourceData.Add(0x00);

        sourceData.AddRange(
            Utils.SplitToByteArray((UInt64)sourceLength)
        );
    }

    private int CalculatePaddingLength(int sourceDataLength) {
        int paddingLength = (int)(_blockLength * 0.875)
                    - (sourceDataLength % _blockLength + 8);

        paddingLength += paddingLength < 0 ? _blockLength : 0;

        return paddingLength;
    }


    private Block[] SplitPaddedDataToBlocks(Byte[] paddedData) {
        int blockLengthInBytes = _blockLength / 8;
        int blocksCount = paddedData.Length / blockLengthInBytes;
			
        Block[] blocks = new Block[blocksCount];

        for(int blockIndex = 0; blockIndex < blocksCount; blockIndex++) {
            Byte[] blockBytes = new Byte[blockLengthInBytes];
            Array.Copy(
                paddedData, 
                blockIndex * blockLengthInBytes, 
                blockBytes, 
                0, 
                blockBytes.Length
            );

            blocks[blockIndex] = new Block(blockBytes);
        }

        return blocks;
    }


    private UInt32[] InitializeWorkingVariables() {
        UInt32[] workingVariables = new UInt32[8];
        
        Array.Copy(
            Constants.InitializeWorkingVariables, 
            workingVariables,
            workingVariables.Length
        );

        return workingVariables;
    }

    
    private void CalculateWordsValues(UInt32[] words) {
        for (int wordIndex = 16; wordIndex < 64; wordIndex++)
            words[wordIndex] = words[wordIndex - 16]
                               + words[wordIndex - 7]
                               + Utils.CalculateSSIG0(words[wordIndex - 15])
                               + Utils.CalculateSSIG1(words[wordIndex - 2]);
    }

    
    private void CalculateHashValues(UInt32[] words, UInt32[] workingVariables) {
        UInt32[] variables = new UInt32[8]; // a - h Variables
        Array.Copy(
            workingVariables, 
            variables,
            variables.Length
        );
        
        for(int iteration = 0; iteration < _iterationsCount; iteration++) {
            // T1 = h + BSIG1(e) + CH(e,f,g) + Kt + Wt
            UInt32 temp1 = variables[(Int32)VariableLetter.H] 
                           + Utils.CalculateBSIG1(variables[(Int32)VariableLetter.E])
                           + Utils.CalculateCH(
                               variables[(Int32)VariableLetter.E], 
                               variables[(Int32)VariableLetter.F], 
                               variables[(Int32)VariableLetter.G]
                            )
                           + Constants.ConstantsTable[iteration] 
                           + words[iteration];

            // T2 = BSIG0(a) + MAJ(a,b,c)
            UInt32 temp2 = Utils.CalculateBSIG0(variables[(Int32)VariableLetter.A]) 
                           + Utils.CalculateMAJ(
                               variables[(Int32)VariableLetter.A], 
                               variables[(Int32)VariableLetter.B], 
                               variables[(Int32)VariableLetter.C]
                            );

            ShiftWorkingVariables(variables);
            variables[(Int32)VariableLetter.A] = temp1 + temp2;
            variables[(Int32)VariableLetter.E] += temp1;
        }

        for (int i = 0; i < workingVariables.Length; i++)
            workingVariables[i] += variables[i];
    }
    
    private void ShiftWorkingVariables(UInt32[] workingVariables) {
        for (int index = workingVariables.Length - 1; index > 0; index--)
            workingVariables[index] = workingVariables[index - 1];
    }

    
    private String ConvertHashValuesToDigest(UInt32[] hashValues) {
        StringBuilder digestBuilder = new StringBuilder();

        foreach(var value in hashValues)
            digestBuilder.Append(
                Convert.ToString(value, 16)
                    .PadLeft(8, '0')
            );

        return digestBuilder.ToString();
    }
}