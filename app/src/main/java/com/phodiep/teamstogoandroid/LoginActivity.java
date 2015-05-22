package com.phodiep.teamstogoandroid;

import android.content.Intent;
import android.net.Uri;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import com.loopj.android.http.AsyncHttpClient;
import com.loopj.android.http.JsonHttpResponseHandler;

import org.json.JSONObject;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;


public class LoginActivity extends ActionBarActivity implements View.OnClickListener {

    EditText usernameTextView;
    EditText passwordTextView;
    Button loginButton;
    Button forgotPasswordButton;
    Button newAccountButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        usernameTextView = (EditText) findViewById(R.id.username_textview);
        passwordTextView = (EditText) findViewById(R.id.password_textview);

        loginButton = (Button) findViewById(R.id.login_button);
        loginButton.setOnClickListener((View.OnClickListener) this);

        forgotPasswordButton = (Button) findViewById(R.id.forgotpassword_button);
        forgotPasswordButton.setOnClickListener((View.OnClickListener) this);

        newAccountButton = (Button) findViewById(R.id.newaccount_button);
        newAccountButton.setOnClickListener((View.OnClickListener) this);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_login, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.login_button :
                try {
                    loginToTeamCowboy();
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                break;

            case R.id.forgotpassword_button :
                forgotPassword();
                break;

            case R.id.newaccount_button :
                newAccount();
                break;

            default:
                break;
        }
    }

    private void loginToTeamCowboy() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        testGetRequest();

    }

    private void forgotPassword() {
        String url = getString(R.string.resetpassword);
        Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
        startActivity(browserIntent);
    }

    private void newAccount() {
        String url = getString(R.string.newaccount);
        Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
        startActivity(browserIntent);
    }

    private String getTimestamp() {
        return Objects.toString(System.currentTimeMillis()/1000, null);
    }

    private String getNonce() {
        return Objects.toString(System.currentTimeMillis()/1000, null);
    }

    private void testGetRequest() throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String url = getString(R.string.httpendpoint);

        String methodCall = "Test_GetRequest";
        Boolean usingSsl = false;
        String timestamp = getTimestamp();
        String nonce = getNonce();
        String publicKey = new ApiKeys().getPublicKey();

        Map<String, String> parameters = new HashMap<String, String>();

        parameters.put("method", methodCall);
        parameters.put("timestamp", timestamp);
        parameters.put("nonce", nonce);
        parameters.put("testParam", "testingGetParam");
        parameters.put("api_key", publicKey);
        parameters.put("response_type", "json");

        //encode values
        Map<String, String> encodedParameters = parameters;

        for (Map.Entry<String, String> entry : encodedParameters.entrySet()) {
            entry.setValue(encodeUrl(entry.getValue()));
        }

        //sortByKeys
        ArrayList sortedKeys = new ArrayList<String>(encodedParameters.keySet());
        Collections.sort(sortedKeys);

        //create queryString for parameters
        ArrayList concatinatedParamaters = new ArrayList();
        for (Object key : sortedKeys) {
            concatinatedParamaters.add(key + "=" + encodedParameters.get(key));
        }
        String queryString = concatListToString(concatinatedParamaters);

        //create signature and hash
        String signature = computeSignatureForQuery(queryString, "GET", methodCall, timestamp, nonce);

        //append hashed signature to queryString
        queryString += "&sig=" + signature;

        //append queryString to endpoint
        url += "?" + queryString;

        Toast.makeText(getApplicationContext(), url, Toast.LENGTH_LONG).show();

        //make request
        AsyncHttpClient client = new AsyncHttpClient();
        client.get(url, new JsonHttpResponseHandler() {
            @Override
            public void onSuccess(JSONObject jsonObject) {
                Toast.makeText(getApplicationContext(), "Success!", Toast.LENGTH_LONG).show();
            }
            public void onFailure(int statusCode, Throwable throwable, JSONObject error) {
                Toast.makeText(getApplicationContext(), "Error: " + statusCode + " " + throwable.getMessage(), Toast.LENGTH_LONG).show();
            }

        });


    }


    private String encodeUrl(String url) throws UnsupportedEncodingException {
        return URLEncoder.encode(url, "utf-8");
    }

    private String concatListToString(ArrayList<String> array) {
        StringBuilder result = new StringBuilder();
        for (String item  : array) {
            result.append(item);
            result.append("&");
        }

        //remove final &
        result.deleteCharAt(result.length()-1);

        return result.toString();
    }

    private String computeSignatureForQuery(String queryString, String httpMethod, String apiMethod, String timestamp, String nonce) throws NoSuchAlgorithmException {
        String lowercaseQueryString = queryString.toLowerCase();

        StringBuilder toSign = new StringBuilder();

        //api, httpMethod, apiMethod, timestamp, nonce, lowercaseQueryString
        toSign.append(new ApiKeys().getPrivateKey());
        toSign.append("|");
        toSign.append(httpMethod);
        toSign.append("|");
        toSign.append(apiMethod);
        toSign.append("|");
        toSign.append(timestamp);
        toSign.append("|");
        toSign.append(nonce);
        toSign.append("|");
        toSign.append(lowercaseQueryString);

        return sha1Encyrpt(toSign.toString());
    }

    private String sha1Encyrpt(String input) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        byte[] result = mDigest.digest(input.getBytes());
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < result.length; i++) {
            sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }
}
