package Wallet;

import javacard.framework.*;

public class CyclicFile 
{

	protected Record[]records;
	public short maxrecord;//��¼�������
	public short recordsize;//��¼��С
	public short currentrecord;//��¼��ǰָ��
	private byte[] buffer;//��������

	protected CyclicFile(short size,short max)//��¼�ļ����캯��
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
	
	public byte[] ReadRecord(short num)//��ȡ��¼
	{
		buffer=records[num].readrecord();
		return buffer;
	}
	
	public short AppendRecord(byte[] data,short size)	//׷�Ӽ�¼
	{
		if(size>recordsize)//���ȹ���
		{
			return (short)1;
		}
		records[currentrecord].changetype(data[0]);
		records[currentrecord].changeamount(data[1]);
		currentrecord++;//ָ��++
		if(currentrecord==maxrecord)//���ˣ�ѭ������һ��
		{
			currentrecord=0;
		}
		return (short)0;
	}



	
}
