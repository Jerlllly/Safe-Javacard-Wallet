package Wallet;

import javacard.framework.*;

public class CyclicFile 
{

	protected Record[]records;
	public short maxrecord;//记录最大条数
	public short recordsize;//记录大小
	public short currentrecord;//记录当前指针
	private byte[] buffer;//声明各项

	protected CyclicFile(short size,short max)//记录文件构造函数
	{
		recordsize = size;
		maxrecord = max;
		records = new Record[max+1];
		currentrecord = 0;
		buffer = JCSystem.makeTransientByteArray(size, JCSystem.CLEAR_ON_DESELECT);
		for(short i=0;i<max;i++)
		{
			records[i]=new Record();
		}
	}
	
	public byte[] ReadRecord(short num)//读取记录
	{
		buffer=records[num].readrecord();
		return buffer;
	}
	
	public short AppendRecord(byte[] data,short size)	//追加记录
	{
		if(size>recordsize)//长度过长
		{
			return (short)1;
		}
		records[currentrecord].changetype(data[0]);
		records[currentrecord].changeamount(data[1]);
		currentrecord++;//指针++
		if(currentrecord==maxrecord)//满了，循环到下一条
		{
			currentrecord=0;
		}
		return (short)0;
	}



	
}
