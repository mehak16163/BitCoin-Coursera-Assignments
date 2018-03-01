import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
public class TxHandler {
	static int why;
    public UTXOPool curr_pool ; 
    public TxHandler(UTXOPool utxoPool) {
        UTXOPool temp = new UTXOPool(utxoPool);
        curr_pool = temp;
    }
    public boolean isValidTx(Transaction tx) {
    	UTXOPool temp = new UTXOPool(curr_pool);
        byte[] hash = tx.getHash();
        int nout = tx.numOutputs();
        int nin = tx.numInputs();
    	//ArrayList<UTXO> curr = temp.getAllUTXO();
        ArrayList<UTXO> pool = new ArrayList<UTXO>();
        double osum=0;//No. of outputs
        double insum=0;//No. of input
        for (int i=0;i<nout;i++){
        	double val=0;
        	val = tx.getOutput(i).value;//Getting the value of that output
        	osum = osum + val;
        	if (val<0){//if val is less than 0 return false;
        		return false;
        	}
        	
        	UTXO ut = new UTXO(hash , i);
        	temp.addUTXO(ut, tx.getOutput(i));
        }
        for(int i=0;i<nin;i++){
        	Transaction.Input inp = tx.getInput(i);
        	if (inp==null)
        		continue;
        	byte[] sig = inp.signature;
        	int oin = inp.outputIndex;
        	byte[] prev = inp.prevTxHash;
        	UTXO pr = new UTXO(prev , oin);
        	if (!temp.contains(pr)){
        		
        		return false;
        	}
        	if (pool.contains(pr))
        		return false;
        	pool.add(pr);
        	double ival = temp.getTxOutput(pr).value;
        	if (ival<0)
        		return false;
        	insum = insum + ival;
        	PublicKey key = temp.getTxOutput(pr).address;
        	byte[] raw = tx.getRawDataToSign(i);
        	if (!Crypto.verifySignature(key, raw, sig)){
        		return false;
        	}
        }
        if (insum<osum){
        	return false;
        }
        else return true;  
    }
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
    	Transaction[] ans = new Transaction[possibleTxs.length];
    	int tot =0;
    	int inc=0;
    	do{
    		inc=0;
    		for (int i=0;i<possibleTxs.length;i++){
    			if (isValidTx(possibleTxs[i])==false){
    				continue;
    			}
    			Transaction tx = possibleTxs[i];
    			byte[] hash = tx.getHash();
    			int out = tx.numOutputs();
    			for(int j=0;j<out;j++){
    				UTXO ut = new UTXO(hash , j);
    				curr_pool.addUTXO(ut, tx.getOutput(j));
    			}
    			int in = tx.numInputs();
    			for(int j=0;j<in;j++){
    				Transaction.Input inp = tx.getInput(j);
    				int oin = inp.outputIndex;
    				byte[] prev = inp.prevTxHash;
    				UTXO pr = new UTXO(prev , oin);
    				curr_pool.removeUTXO(pr);
    			}
    			ans[tot] = tx;
    			tot++;
    			inc++;
    		}
    	}
    	while(inc>0);
    	Transaction[] result = new Transaction[tot];
    	for(int i=0;i<tot;i++){
    		result[i]=ans[i];
    	}
    	
    	return result;
    }
}
