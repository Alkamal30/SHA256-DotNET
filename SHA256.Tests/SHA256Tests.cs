using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Hashing.SHA256.Tests;

public class SHA256Tests {

	[Theory]
	[InlineData("qwerty", "65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5")]
	[InlineData("Hello, World!", "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f")]
	[InlineData("The five boxing wizards jump quickly", "44a3a7b6e5c39c1b17458a5b3a9f2f4e6dbb624dc65b23ab3d305562c3744f9b")]
	[InlineData("Jackdaws love my big sphinx of quartz", "f118871c45171d5fe4e9049980959e033eeeabcfa12046c243fda310580e8a0b")]
	[InlineData("The quick brown fox jumps over the lazy dog", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")]
	public void HashMessageTest(String message, String expectedHash) {
		// Arrange
		SHA256 sha256 = new SHA256();
		
		// Act
		String actualHash = sha256.HashMessage(message);

		// Assert
		Assert.Equal(expectedHash, actualHash);
	}

}
