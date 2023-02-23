namespace Hashing.SHA256; 

public class Block {

    public Block() : this(64) { }
    
    public Block(int size) {
        _bytes = new Byte[size];
    }

    public Block(Byte[] bytes) {
        _bytes = bytes;
    }


    public Byte this[int index] {
        get {
            return _bytes[index];
        }
        set {
            _bytes[index] = value;
        }
    }
    
    public int Size => _bytes.Length;
    
    
    private Byte[] _bytes;
}