package Wallet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class ExternalAuthentication {

	byte [] Random;
	private DESKey deskey;
	Cipher  CipherObj;
	short flag=0x00;
	  //����DES��Կ
	private byte[] keyData = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
	  

public void doAuthentication(byte [] buffer) {
			
	
		//������Կ����
	      deskey=(DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
							
	      //���ãģţ���Կ					
	      deskey.setKey(keyData, (short)0);
	      
	      //���ɼ��ܶ���
	      CipherObj   = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
	      
	      //��ʼ����Կ������ģʽ
	      CipherObj.init(deskey, Cipher.MODE_ENCRYPT);
	      
	       //����
	       CipherObj.doFinal(Random, (short)0, (short)8, buffer, (short)13); 
	       
	       //�Ƚ�����������ܽ��
	       if ( Util.arrayCompare(buffer,(short)5, buffer, (short)13,(short)8)
	    		   != 0 )
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
	       else
	    	   flag=0x01;
	}

	public void getRandom() {
		
		//������������������
		if ( Random == null )
			Random = JCSystem.makeTransientByteArray((short)16,JCSystem.CLEAR_ON_DESELECT);
		
		//�������������Ķ���ʵ��
		RandomData ICC = RandomData.getInstance((byte)RandomData.ALG_PSEUDO_RANDOM );
		
		//��������������Ӳ�����8�ֽڵ������
		ICC.setSeed(Random,(short)0,(short)8 );
        ICC.generateData(Random,(short)0,(short)8);

	}
	public short getFlag()
	{
		short result=flag;
		return result;
	}
}
