namespace Hashing.SHA256; 

public static class Utils {

    private enum TypeLength {
        UInt16 = 16,
        UInt32 = 32,
        UInt64 = 64,
    }


    #region [SHA256FunctionsRegion]

    // CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)
    public static UInt32 CalculateCH(UInt32 xValue, UInt32 yValue, UInt32 zValue) 
        => (xValue & yValue) ^ (~xValue & zValue);

    // MAJ( x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
    public static UInt32 CalculateMAJ(UInt32 xValue, UInt32 yValue, UInt32 zValue)
        => (xValue & yValue) ^ (xValue & zValue) ^ (yValue & zValue);

    // BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)
    public static UInt32 CalculateBSIG0(UInt32 value)
        => Utils.CircularRightShift(value, 2)
           ^ Utils.CircularRightShift(value, 13)
           ^ Utils.CircularRightShift(value, 22);
    
    // BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
    public static UInt32 CalculateBSIG1(UInt32 value)
        => Utils.CircularRightShift(value, 6)
           ^ Utils.CircularRightShift(value, 11)
           ^ Utils.CircularRightShift(value, 25);

    // SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
    public static UInt32 CalculateSSIG0(UInt32 value)
        => Utils.CircularRightShift(value, 7)
           ^ Utils.CircularRightShift(value, 18)
           ^ (value >> 3);

    // SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)
    public static UInt32 CalculateSSIG1(UInt32 value)
        => Utils.CircularRightShift(value, 17)
           ^ Utils.CircularRightShift(value, 19)
           ^ (value >> 10);

    #endregion

    #region [BlockFunctionsRegion]

    public static UInt32[] SplitBlockToWords(Block block) {
        UInt32[] words = new UInt32[64];

        for(int wordIndex = 0; wordIndex < 16; wordIndex++) {
            int blockByteIndex = wordIndex * 4;
            
            words[wordIndex] |= (UInt32)(block[blockByteIndex++] << 24);
            words[wordIndex] |= (UInt32)(block[blockByteIndex++] << 16);
            words[wordIndex] |= (UInt32)(block[blockByteIndex++] << 8);
            words[wordIndex] |= (UInt32)(block[blockByteIndex]);
        }

        return words;
    }

    #endregion
    
    #region [SplitRegion]

    public static Byte[] SplitToByteArray(UInt64 value)
        => SplitToByteArrayWithFixedWidth(value, (Int32) TypeLength.UInt64);
    
    public static Byte[] SplitToByteArray(UInt32 value)
        => SplitToByteArrayWithFixedWidth(value, (Int32) TypeLength.UInt32);
    
    public static Byte[] SplitToByteArray(UInt16 value)
        => SplitToByteArrayWithFixedWidth(value, (Int32) TypeLength.UInt16);

    private static Byte[] SplitToByteArrayWithFixedWidth(UInt64 value, int typeWidth) {
        Byte[] byteArray = new Byte[typeWidth / 8];
        int mask = typeWidth - 8;

        for(int byteIndex = 0; byteIndex < byteArray.Length; byteIndex++, mask -= 8)
            byteArray[byteIndex] = (Byte)((value >> mask) & 0xFF);

        return byteArray;
    }

    #endregion

    #region [CircularShiftRegion]
    
    public static UInt64 CircularLeftShift(UInt64 value, int shiftValue)
        => CircularLeftShiftWithFixedWidth(value, shiftValue, (Int32) TypeLength.UInt64);
    
    public static UInt32 CircularLeftShift(UInt32 value, int shiftValue) 
        => (UInt32) CircularLeftShiftWithFixedWidth(value, shiftValue, (Int32) TypeLength.UInt32);

    public static UInt16 CircularLeftShift(UInt16 value, int shiftValue) 
        => (UInt16) CircularLeftShiftWithFixedWidth(value, shiftValue, (Int32) TypeLength.UInt16);

    
    public static UInt64 CircularRightShift(UInt64 value, int shiftValue)
        => CircularRightShiftWithFixedWidth(value, shiftValue, (Int32) TypeLength.UInt64);
    
    public static UInt32 CircularRightShift(UInt32 value, int shiftValue) 
        => (UInt32) CircularRightShiftWithFixedWidth(value, shiftValue, (Int32) TypeLength.UInt32);

    public static UInt16 CircularRightShift(UInt16 value, int shiftValue) 
        => (UInt16) CircularRightShiftWithFixedWidth(value, shiftValue, (Int32) TypeLength.UInt16);
    

    private static UInt64 CircularLeftShiftWithFixedWidth(UInt64 value, int shiftValue, int width)
        => CircularShift(
            value, shiftValue, width, 
            (val, shift) => (val << shift), 
            (val, shift) => (val >> shift)
        );

    private static UInt64 CircularRightShiftWithFixedWidth(UInt64 value, int shiftValue, int width)
        => CircularShift(
            value, shiftValue, width, 
            (val, shift) => (val >> shift), 
            (val, shift) => (val << shift)
        );

    private static UInt64 CircularShift(
        UInt64 value, int shiftValue, int width, 
        Func<UInt64, int, UInt64> directOperation,
        Func<UInt64, int, UInt64> reverseOperation) {

        shiftValue %= width;
        return directOperation(value, shiftValue) | reverseOperation(value, width - shiftValue);
    }
    
    #endregion
}
