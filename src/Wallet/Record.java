package Wallet;

public class Record 
{
	private byte transtype;
	private byte transamount;
	public void changetype(byte temp)
	{
		transtype=temp;
	}
	public void changeamount(byte temp)
	{
		transamount=temp;
	}
	public byte []readrecord()
	{
		byte []buffer=new byte[2];
		buffer[0]=transtype;
		buffer[1]=transamount;
		return buffer;
	}
}
