using Hashing.SHA256;

namespace Hashing.SHA256.Tests;

public class UtilsTests {

    #region [SHA256FunctionsRegion]

    [Theory]
    [InlineData(0x7A4FCEB7, 0x573423E5, 0x1F1BC793, 0x571403A5)]
    [InlineData(0xC7779336, 0xFE0D0092, 0xB4C65293, 0xF6854093)]
    public static void CalculateCHTest(UInt32 xValue, UInt32 yValue, UInt32 zValue, UInt32 expected) {
        // Act
        UInt32 actual = Utils.CalculateCH(xValue, yValue, zValue);

        // Assert
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(0x03F8D13F, 0x211337D4, 0x7BBC2201, 0x23B83315)]
    [InlineData(0xC7DE33C0, 0xA208320F, 0xED40A777, 0xE7483347)]
    public static void CalculateMAJTest(UInt32 xValue, UInt32 yValue, UInt32 zValue, UInt32 expected) {
        // Act
        UInt32 actual = Utils.CalculateMAJ(xValue, yValue, zValue);

        // Assert
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(0xC7DE33C0, 0xD73EB11E)]
    [InlineData(0xA48771A2, 0x39F272C1)]
    public static void CalculateBSIG0Test(UInt32 value, UInt32 expected) {
        // Act
        UInt32 actual = Utils.CalculateBSIG0(value);

        // Assert
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(0x0C2302BB, 0xAAD055EC)]
    [InlineData(0x6C30D1EC, 0x9455B36B)]
    public static void CalculateBSIG1Test(UInt32 value, UInt32 expected) {
        // Act
        UInt32 actual = Utils.CalculateBSIG1(value);

        // Assert
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(0x313042AD, 0x4CEF249C)]
    [InlineData(0x0C8D20C2, 0xCDB83D7A)]
    public static void CalculateSSIG0Test(UInt32 value, UInt32 expected) {
        // Act
        UInt32 actual = Utils.CalculateSSIG0(value);

        // Assert
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(0xD830F5A4, 0x6450FB23)]
    [InlineData(0xF4905CEE, 0x25D780CD)]
    public static void CalculateSSIG1Test(UInt32 value, UInt32 expected) {
        // Act
        UInt32 actual = Utils.CalculateSSIG1(value);

        // Assert
        Assert.Equal(expected, actual);
    }

    #endregion

    #region [BlockFunctionsRegion]

    [Fact]
    public static void SplitBlockToWords() {
        // Arrange
        Block block = new Block(new Byte[] { // Padded "The quick brown fox jumps over the lazy dog" message in bytes
			0x54, 0x68, 0x65, 0x20, 
            0x71, 0x75, 0x69, 0x63, 
            0x6B, 0x20, 0x62, 0x72, 
            0x6F, 0x77, 0x6E, 0x20, 
            0x66, 0x6F, 0x78, 0x20, 
            0x6A, 0x75, 0x6D, 0x70, 
            0x73, 0x20, 0x6F, 0x76, 
            0x65, 0x72, 0x20, 0x74, 
            0x68, 0x65, 0x20, 0x6C, 
            0x61, 0x7A, 0x79, 0x20, 
            0x64, 0x6F, 0x67, 0x00, 
            0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00,
		});

        UInt32[] blockWords = {
            0x54686520,
            0x71756963,
            0x6B206272,
            0x6F776E20,
            0x666F7820,
            0x6A756D70,
            0x73206F76,
            0x65722074,
            0x6865206C,
            0x617A7920,
            0x646F6700,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
        };

		// Act
		UInt32[] expected = new UInt32[64];
        Array.Copy(blockWords, expected, blockWords.Length);

        UInt32[] actual = Utils.SplitBlockToWords(block);

        // Assert
        Assert.Equal(expected, actual);
	}

	#endregion

	#region [SplitRegion]

	[Theory]
    [InlineData(0x1122334455667788, new Byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 })]
    [InlineData(0x8877665544332211, new Byte[] { 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 })]
    [InlineData(0x0123456789ABCDEF, new Byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF })]
    public static void SplitUInt64ToByteArrayTest(UInt64 value, Byte[] expected) {
        // Act
        Byte[] actual = Utils.SplitToByteArray(value);

        // Assert
        Assert.Equal(expected, actual);
    }

	[Theory]
	[InlineData(0xAF1940BB, new Byte[] { 0xAF, 0x19, 0x40, 0xBB })]
	[InlineData(0x1011BCDF, new Byte[] { 0x10, 0x11, 0xBC, 0xDF })]
	[InlineData(0x49B02FC1, new Byte[] { 0x49, 0xB0, 0x2F, 0xC1 })]
	public static void SplitUInt32ToByteArrayTest(UInt32 value, Byte[] expected) {
		// Act
		Byte[] actual = Utils.SplitToByteArray(value);

		// Assert
		Assert.Equal(expected, actual);
	}

	[Theory]
	[InlineData(0x28B1, new Byte[] { 0x28, 0xB1 })]
	[InlineData(0x9F28, new Byte[] { 0x9F, 0x28 })]
	[InlineData(0xABCD, new Byte[] { 0xAB, 0xCD })]
	public static void SplitUInt16ToByteArrayTest(UInt16 value, Byte[] expected) {
		// Act
		Byte[] actual = Utils.SplitToByteArray(value);

		// Assert
		Assert.Equal(expected, actual);
	}

    #endregion

    #region [CircularShiftRegion]

    [Theory]
    [InlineData(0x1122334455667788, 4, 0x1223344556677881)]
    [InlineData(0x8877665544332211, 80, 0x6655443322118877)]
    [InlineData(0xA8B4D50C12FF47E3, 25, 0x1825FE8FC75169AA)]
    public static void CircularLeftShiftUInt64Test(UInt64 value, int shiftValue, UInt64 expected) {
        // Act
        UInt64 actual = Utils.CircularLeftShift(value, shiftValue);

        // Assert
        Assert.Equal(expected, actual);
    }

	[Theory]
	[InlineData(0x88664422, 80, 0x44228866)]
	[InlineData(0xA80C17E3, 17, 0x2FC75018)]
	public static void CircularLeftShiftUInt32Test(UInt32 value, int shiftValue, UInt32 expected) {
		// Act
		UInt32 actual = Utils.CircularLeftShift(value, shiftValue);

		// Assert
		Assert.Equal(expected, actual);
	}

	[Theory]
	[InlineData(0x1234, 80, 0x1234)]
	[InlineData(0x8C1E, 11, 0xF460)]
	public static void CircularLeftShiftUInt16Test(UInt16 value, int shiftValue, UInt16 expected) {
		// Act
		UInt16 actual = Utils.CircularLeftShift(value, shiftValue);

		// Assert
		Assert.Equal(expected, actual);
	}


	[Theory]
	[InlineData(0x0123456789ABCDEF, 70, 0xBC048D159E26AF37)]
	[InlineData(0x8C22F60BF1E14D5A, 23, 0xC29AB51845EC17E3)]
	public static void CircularRightShiftUInt64Test(UInt64 value, int shiftValue, UInt64 expected) {
		// Act
		UInt64 actual = Utils.CircularRightShift(value, shiftValue);

		// Assert
		Assert.Equal(expected, actual);
	}

	[Theory]
	[InlineData(0x02468ACE, 34, 0x8091A2B3)]
	[InlineData(0x8CF1E14D, 23, 0xE3C29B19)]
	public static void CircularRightShiftUInt32Test(UInt32 value, int shiftValue, UInt32 expected) {
		// Act
		UInt32 actual = Utils.CircularRightShift(value, shiftValue);

		// Assert
		Assert.Equal(expected, actual);
	}

	[Theory]
	[InlineData(0x1234, 18, 0x048D)]
	[InlineData(0x8C1E, 3, 0xD183)]
	public static void CircularRightShiftUInt16Test(UInt16 value, int shiftValue, UInt16 expected) {
		// Act
		UInt16 actual = Utils.CircularRightShift(value, shiftValue);

		// Assert
		Assert.Equal(expected, actual);
	}

	#endregion
}