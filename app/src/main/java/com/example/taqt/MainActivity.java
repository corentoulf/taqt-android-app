package com.example.taqt;

import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.Resources;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.Ndef;
import android.nfc.tech.NdefFormatable;
import android.nfc.tech.NfcA;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsControllerCompat;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";
    private PendingIntent pendingIntent;
    private String[][] techListsArray;
    private NfcAdapter mAdapter;
    private IntentFilter[] mFilters;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WindowInsetsControllerCompat windowInsetsController =
                ViewCompat.getWindowInsetsController(getWindow().getDecorView());
        if (windowInsetsController == null) {
            return;
        }
        setContentView(R.layout.activity_main);
        mAdapter = NfcAdapter.getDefaultAdapter(this);
        //Declare pending Intent
        pendingIntent = PendingIntent.getActivity(
                this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PendingIntent.FLAG_MUTABLE);

        //Declare intent filter
        IntentFilter ndef = new IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED);
        try {
            ndef.addDataType("*/*");    /* Handles all MIME based dispatches.
                                       You should specify only the ones that you need. */
        } catch (IntentFilter.MalformedMimeTypeException e) {
            throw new RuntimeException("fail", e);
        }
        mFilters = new IntentFilter[]{ndef,};

        //declare techList
        techListsArray = new String[][]{
                new String[]{NfcA.class.getName()},
                new String[]{Ndef.class.getName()},
        };

    }

    @Override
    public void onResume() {
        super.onResume();
        mAdapter.enableForegroundDispatch(this, pendingIntent, mFilters, techListsArray);
    }

    @Override
    public void onPause() {
        super.onPause();
        mAdapter.disableForegroundDispatch(this);
    }

    @Override
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        Resources res = getResources();
        Log.i(TAG, "A NFC tag was detected");
        //A Tag was detected
        Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        //show ID
        String tagId = GFG.convertByteToHexadecimal(tag.getId());
        Log.i(TAG, "Tag Id : "+ tagId);

        //calc key
        String encryptedTagId = encryptTagId(tagId);
        Log.i(TAG, "Encrypted tag Id : "+ encryptedTagId);

        //prepare NdefRecord
        NdefRecord encryptedTagRecord = NdefRecord.createTextRecord("fr", "key:"+encryptedTagId);

        //scan tag records and detect key already there
        Parcelable[] rawMessages =
                intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES);
        //if there are already one or more messages wrote tag
        if (rawMessages != null) {
            boolean foundTaqtEncKey = false;
            //considering only 1 NdefMessage
            NdefMessage tagMessages = (NdefMessage) rawMessages[0];//create a Ndef[] array with a length equal to number of message
            NdefRecord[] ndefRecords = tagMessages.getRecords();
            Log.i(TAG, rawMessages.length + " message(s) were found on tag. First message contains "+ndefRecords.length+" records.");
            for (int i = 0; i < ndefRecords.length; i++) {
                Log.i(TAG, String.valueOf(ndefRecords[i]));
                byte[] recordPayload = ndefRecords[i].getPayload();
                /*
                     * payload[0] contains the "Status Byte Encodings" field, per the
                     * NFC Forum "Text Record Type Definition" section 3.2.1.
                     *
                     * bit7 is the Text Encoding Field.
                     *
                     * if (Bit_7 == 0): The text is encoded in UTF-8 if (Bit_7 == 1):
                     * The text is encoded in UTF16
                     *
                     * Bit_6 is reserved for future use and must be set to zero.
                     *
                     * Bits 5 to 0 are the length of the IANA language code.
                 */
                //Get the Text Encoding
                String textEncoding = ((recordPayload[0] & 0200) == 0) ? "UTF-8" : "UTF-16";

                //Get the Language Code
                int languageCodeLength = recordPayload[0] & 0077;
                //String languageCode = new String(recordPayload, 1, languageCodeLength, "US-ASCII");
                //Get the Text
                try {
                    String payloadText = new String(recordPayload, languageCodeLength + 1, recordPayload.length - languageCodeLength - 1, textEncoding);
                    //Parse payload to detect Taqt encryption key
                    String[] payloadArr = payloadText.split(":");

                    if( payloadArr[0].equals("key") ) {
                        foundTaqtEncKey = true;
                        Log.i(TAG, "found a record with a 'key' index : '" + payloadText + "' (n°"+i+"). Replacing with a fresh one.");
                        ndefRecords[i] = encryptedTagRecord;
                    }
                    else {
                        Log.i(TAG, "Leaving unchanged record n°"+ i);
                    }
                } catch (UnsupportedEncodingException e) {
                    Log.i(TAG, "error");
                    TextView tvWriteStatus = findViewById(R.id.tagWriteResult);
                    tvWriteStatus.setText(res.getString(R.string.tag_write_failed));
                    e.printStackTrace();
                }
            }
            //if taqt encryption key never found, add it
            if(!foundTaqtEncKey){
                Log.i(TAG, "No Taqt encryption key were found. Adding it.");
                NdefRecord[] newNdefRecords = new NdefRecord[ndefRecords.length+1];
                newNdefRecords[newNdefRecords.length -1] = encryptedTagRecord;
                System.arraycopy(ndefRecords, 0, newNdefRecords, 0, ndefRecords.length);
                NdefMessage updateCreateMsg = new NdefMessage(
                        newNdefRecords
                );
                writeTag(tag, updateCreateMsg);
                //tagWriteResult : adding among other tag records
                TextView tvWriteStatus = findViewById(R.id.tagWriteResult);
                tvWriteStatus.setText(res.getString(R.string.tag_write_add_success));
            }
            else {
                NdefMessage updateMsg = new NdefMessage(
                        ndefRecords
                );
                writeTag(tag, updateMsg);
                TextView tvWriteStatus = findViewById(R.id.tagWriteResult);
                tvWriteStatus.setText(res.getString(R.string.tag_write_update_success));
            }
        }
        else {
            NdefMessage newMsg = new NdefMessage(
                    encryptedTagRecord
            );
            Log.i(TAG, "There are NO messages in this tag, we can write the key");
            writeTag(tag, newMsg);
            //tagWriteResult : added encryption
            TextView tvWriteStatus = findViewById(R.id.tagWriteResult);
            tvWriteStatus.setText(res.getString(R.string.tag_write_add_success));
        }

        // display ID on screen
        TextView tvNfcDisplay = findViewById(R.id.tagDetectedId);
        //Show title
        TextView tvTagDetected = findViewById(R.id.tagDetected);
        tvTagDetected.setVisibility(View.VISIBLE);
        tvNfcDisplay.setText(tagId);
    }

    public void writeTag(Tag tag, NdefMessage message)  {
        Resources res = getResources();
        if (tag != null) {
            try {
                Ndef ndefTag = Ndef.get(tag);
                if (ndefTag == null) {
                    // Let's try to format the Tag in NDEF
                    NdefFormatable nForm = NdefFormatable.get(tag);
                    if (nForm != null) {
                        nForm.connect();
                        nForm.format(message);
                        nForm.close();
                    }
                }
                else {
                    ndefTag.connect();
                    ndefTag.writeNdefMessage(message);
                    ndefTag.close();
                }
                Log.i(TAG, "wrote on tag.");
            }
            catch(Exception e) {
                //tagWriteResult : fail writing
                e.printStackTrace();
                TextView tvWriteStatus = findViewById(R.id.tagWriteResult);
                tvWriteStatus.setText(res.getString(R.string.tag_write_failed));
            }
        }
    }

    @NonNull
    static String encryptTagId(String tagId) {
        String keyHex = "AA"; //the key to encrypt
        //parse key in blocks of 2 characters
        Pattern pattern = Pattern.compile(".{2}");
        List<String> res = new ArrayList<>();
        Matcher matcher = pattern.matcher(tagId);
        while (matcher.find()){
            res.add(matcher.group(0));
        }
        //recreate array
        String [] tagArr = res.toArray(new String[0]);
        //prepare encrypted array of blocks
        String [] tagArrEnc = res.toArray(new String[0]);
        //calculate complement to FF
        for (int i = 0; i < tagArr.length; i++) {
            //complement to FF
            Integer compToFF = Integer.parseInt("ff", 16) - Integer.parseInt(tagArr[i], 16);
            //XOR to key
            Integer xorKey = compToFF ^ Integer.parseInt(keyHex, 16);
            //to hex
            String encKeyHex = String.format("%1$02X", xorKey);
            //populate array
            tagArrEnc[i] = encKeyHex;
        }
        Collections.reverse(Arrays.asList(tagArrEnc));
        return String.join("", tagArrEnc);
    }
}
class GFG {
    static String convertByteToHexadecimal(byte[] byteArray)
    {
        String hex = "";

        // Iterating through each byte in the array
        for (byte i : byteArray) {
            hex += String.format("%02X", i);
        }

        return hex;
    }
}

