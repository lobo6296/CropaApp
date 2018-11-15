/**
 * Author: Ravi Tamada
 * URL: www.androidhive.info
 * twitter: http://twitter.com/ravitamada
 * con permisos de autor copio
 */
package info.androidhive.loginandregistration.activity;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.Intent;
import android.os.Bundle;
import android.os.StrictMode;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import com.android.volley.Request.Method;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.StringRequest;

import org.json.JSONException;
import org.json.JSONObject;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import info.androidhive.loginandregistration.R;
import info.androidhive.loginandregistration.app.AppConfig;
import info.androidhive.loginandregistration.app.AppController;
import info.androidhive.loginandregistration.helper.SQLiteHandler;
import info.androidhive.loginandregistration.helper.SessionManager;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.TimeZone;

import android.content.Context;



public class LoginActivity extends Activity {
    HttpURLConnection httpCon;

    private static final String TAG = RegisterActivity.class.getSimpleName();
    private Button btnLogin;
    private Button btnLinkToRegister;
    private EditText inputEmail;
    private EditText inputPassword;
    private ProgressDialog pDialog;
    private SessionManager session;
    private SQLiteHandler db;
    private boolean huboError;


    public String genNonce() {
        int flags = Base64.DEFAULT;
        java.security.SecureRandom random = new java.security.SecureRandom();
        random.setSeed(System.currentTimeMillis());
        byte[] nonceBytes = new byte[16];
        random.nextBytes(nonceBytes);
        String nonce = Base64.encodeToString(nonceBytes,flags);
     return nonce;
    }

    private String generateTimestamp() {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return sdf.format(new Date());
    }

    public String postThroughHttpUrlConnection(String puser,String ppassword) {
        StringBuffer response = new StringBuffer();
        String respuesta="";

        try {
            huboError=false;
            StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
            StrictMode.setThreadPolicy(policy);

            User user = new User("jose","4dm1n");
            httpCon = (HttpURLConnection) new URL(AppConfig.URL_LOGIN).openConnection();
            httpCon.setDoOutput(true);
            httpCon.setDoInput(true);
            httpCon.setUseCaches(false);
            httpCon.setChunkedStreamingMode(0);
            int flags = Base64.DEFAULT;
            MessageDigest messageDigest= null;
            try {
                messageDigest = MessageDigest.getInstance("SHA-1");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }

            String nonce=genNonce();
            String created=generateTimestamp();
            String pwd=user.getPassword();

            byte[] nonceBytes = Base64.decode(nonce,flags);
            byte[] createdBytes = created.getBytes("UTF-8");
            byte[] passwordBytes = pwd.getBytes("UTF-8");
            byte[] concatenatedBytes = new byte[nonceBytes.length
                    + createdBytes.length + passwordBytes.length];

            int offset = 0;
            System.arraycopy(nonceBytes, 0, concatenatedBytes, offset, nonceBytes.length);
            offset += nonceBytes.length;
            System.arraycopy(createdBytes, 0, concatenatedBytes, offset,createdBytes.length);
            offset += createdBytes.length;
            System.arraycopy(passwordBytes, 0, concatenatedBytes, offset,passwordBytes.length);
            messageDigest.update(concatenatedBytes);
            String passwordDiggest=Base64.encodeToString(messageDigest.digest(),Base64.DEFAULT);

            String soapEnvlop = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                                "<soapenv:Envelope xmlns:crop=\"https://cropa.com.gt/ws/CROPAService\" " +
                                "                  xmlns:oas=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" " +
                                "                  xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                                "<soapenv:Header>\n" +
                                "<oas:Security soapenv:mustUnderstand=\"1\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">\n" +
                                "         <oas:UsernameToken wsu:Id=\"UsernameToken-732B11CA7D6B74B7BB15231583744591\">\n" +
                                "            <oas:Username>"+user.getUsername()+"</oas:Username>\n" +
                                "            <oas:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">"+passwordDiggest+"</oas:Password>\n" +
                                "            <oas:Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">"+nonce+"</oas:Nonce>\n" +
                                "            <wsu:Created>"+created+"</wsu:Created>\n" +
                                "         </oas:UsernameToken>\n" +
                                "      </oas:Security>\n" +
                                "   </soapenv:Header>\n"+
                                "<soapenv:Body>"+
                                "      <crop:ValidateUserRequestParms>\n" +
                                "         <crop:Username>jose.rivera@cropa.com.gt</crop:Username>\n" +
                                "         <crop:Password>4dm1n</crop:Password>\n" +
                                "      </crop:ValidateUserRequestParms>\n" +
                                "   </soapenv:Body>"+
                                "</soapenv:Envelope>";

            Log.i(TAG, "vls: Request: " + soapEnvlop);

            Log.i(TAG, "vls: Usuario: " + user.getUsername());
            Log.i(TAG, "vls: pwddigest: " + passwordDiggest);
            Log.i(TAG, "vls: Nonce: " + nonce);
            Log.i(TAG, "vls: Created: " + created);


            httpCon.addRequestProperty("Accept-Encoding", "gzip,deflate");
            httpCon.addRequestProperty("Content-Type", "text/xml;charset=UTF-8");
            httpCon.addRequestProperty("SOAPAction", "");
            httpCon.addRequestProperty("Content-Length", ""+soapEnvlop.length());
            httpCon.addRequestProperty("Host", "cropa.com.gt");
            httpCon.setRequestMethod("POST");

            OutputStream out = new BufferedOutputStream(httpCon.getOutputStream());
            out.write(soapEnvlop.getBytes());
            out.flush();
            out.close();

            //Get Response
            InputStream is ;

            if(httpCon.getResponseCode()<=400){
                is=httpCon.getInputStream();

            }else{
                /* error from server */
                is = httpCon.getErrorStream();

            }

            BufferedReader rd = new BufferedReader(new InputStreamReader(is));
            String line;


            while((line = rd.readLine()) != null) {
                response.append(line);
                response.append('\r');
            }

            rd.close();

            respuesta=response.toString();

            Log.i(TAG, "vls: Response: \n\n" + response);


        } catch (MalformedURLException e1) {
            Log.i(TAG, "vls: URL Malformed");
            huboError=true;
        } catch (IOException e1) {
            Log.i(TAG, "vls: Error Entrada/Salida");
            Log.i(TAG, "vls: "+ e1.getMessage());
            huboError=true;
        } finally {
            if (httpCon != null) {
                httpCon.disconnect();
            }
        }
        return respuesta;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        inputEmail = (EditText) findViewById(R.id.email);
        inputPassword = (EditText) findViewById(R.id.password);
        btnLogin = (Button) findViewById(R.id.btnLogin);
        btnLinkToRegister = (Button) findViewById(R.id.btnLinkToRegisterScreen);

        // Progress dialog
        pDialog = new ProgressDialog(this);
        pDialog.setCancelable(false);

        // SQLite database handler
        db = new SQLiteHandler(getApplicationContext());

        // Session manager
        session = new SessionManager(getApplicationContext());

        // Check if user is already logged in or not
        /*
        if (session.isLoggedIn()) {
            // User is already logged in. Take him to main activity
            Intent intent = new Intent(LoginActivity.this, MainActivity.class);
            startActivity(intent);
            finish();
        }
        */

        // Login button Click Event
        btnLogin.setOnClickListener(new View.OnClickListener() {

            public void onClick(View view) {
                String email = inputEmail.getText().toString().trim();
                String password = inputPassword.getText().toString().trim();

                // Check for empty data in the form
                if (!email.isEmpty() && !password.isEmpty()) {
                    // login user
                    checkLogin(email, password);
                } else {
                    // Prompt user to enter credentials
                    Toast.makeText(getApplicationContext(),
                            "Please enter the credentials!", Toast.LENGTH_LONG)
                            .show();
                }
            }

        });

        // Link to Register Screen
        btnLinkToRegister.setOnClickListener(new View.OnClickListener() {

            public void onClick(View view) {
                Intent i = new Intent(getApplicationContext(),
                        RegisterActivity.class);
                startActivity(i);
                finish();
            }
        });

    }

    /**
     * function to verify login details in mysql db
     * */
    public static String getTag(String nombretag, String xmldata)
    {
        String retorno="";
        if ((xmldata.indexOf("<"+nombretag+">")>=0) && (xmldata.indexOf("</"+nombretag+">")>=0))
        {
            retorno=xmldata.substring( xmldata.indexOf("<"+nombretag+">")+nombretag.length()+2,
                    xmldata.indexOf("</"+nombretag+">"));
            retorno=retorno.trim();
        }
        return(retorno);
    }

    private void checkLogin(final String email, final String password) {
        // Tag used to cancel the request
        String tag_string_req = "req_login";
        String respuesta="";
        int resultCode=-1;

        pDialog.setMessage("Logging in ...");
        Log.i(TAG, "vls: checkLogin: " + email+","+password);
        showDialog();
        Log.i(TAG, "vls: URL_LOGIN: " + AppConfig.URL_LOGIN);

        respuesta=postThroughHttpUrlConnection(email,password);

        if (respuesta.contains("faultstring")) {
            String errorMsg = this.getTag("faultstring",respuesta);
            Toast.makeText(getApplicationContext(),
                    errorMsg, Toast.LENGTH_LONG).show();
            hideDialog();
        }
        else {
            resultCode = Integer.parseInt(this.getTag("crp:ResultCode", respuesta));
            hideDialog();

            if (this.huboError||resultCode!=0) {
                String errorMsg = "Ocurrio un error inesperado!";
                Toast.makeText(getApplicationContext(),
                        errorMsg, Toast.LENGTH_LONG).show();
            }
            else {
                session.setLogin(true);
                // db.addUser(name, email, uid, created_at);

                // Launch main activity
                Intent intent = new Intent(LoginActivity.this, DashboardActivity.class);
                startActivity(intent);
                finish();
            }
        }



        /*
        StringRequest strReq = new StringRequest(Method.POST, AppConfig.URL_LOGIN, new Response.Listener<String>() {

            @Override
            public void onResponse(String response) {
                Log.i(TAG, "vls: Login Response: " + response);
                hideDialog();

                try {
                    JSONObject jObj = new JSONObject(response);
                    boolean error = jObj.getBoolean("error");

                    // Check for error node in json
                    if (!error) {
                        // user successfully logged in
                        // Create login session
                        session.setLogin(true);

                        // Now store the user in SQLite
                        String uid = jObj.getString("uid");

                        JSONObject user = jObj.getJSONObject("user");
                        String name = user.getString("name");
                        String email = user.getString("email");
                        String created_at = user.getString("created_at");

                        // Inserting row in users table
                        db.addUser(name, email, uid, created_at);

                        // Launch main activity
                        Intent intent = new Intent(LoginActivity.this,
                                MainActivity.class);
                        startActivity(intent);
                        finish();
                    } else {
                        // Error in login. Get the error message
                        String errorMsg = jObj.getString("error_msg");
                        Toast.makeText(getApplicationContext(),
                                errorMsg, Toast.LENGTH_LONG).show();
                    }
                } catch (JSONException e) {
                    // JSON error
                    e.printStackTrace();
                    Toast.makeText(getApplicationContext(), "Json error: " + e.getMessage(), Toast.LENGTH_LONG).show();
                }

            }
        }, new Response.ErrorListener() {

            @Override
            public void onErrorResponse(VolleyError error) {
                Log.e(TAG, "Login Error: " + error.getMessage());
                Toast.makeText(getApplicationContext(),
                        error.getMessage(), Toast.LENGTH_LONG).show();
                hideDialog();
            }
        }) {

            @Override
            protected Map<String, String> getParams() {
                // Posting parameters to login url
                Map<String, String> params = new HashMap<>();
                params.put("Username", email);
                params.put("Password", password);

                return params;
            }

        };

        // Adding request to request queue
        AppController.getInstance().addToRequestQueue(strReq, tag_string_req);
        */



    }

    private void showDialog() {
        if (!pDialog.isShowing())
            pDialog.show();
    }

    private void hideDialog() {
        if (pDialog.isShowing())
            pDialog.dismiss();
    }
}
