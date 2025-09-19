public class MegaVulnerableService {

    // Hardcoded secrets
    private String apiKey = '123SECRET';
    private String password = 'MyPassw0rd!';

    // Insecure HTTP endpoint
    public void sendData() {
        HttpRequest req = new HttpRequest();
        req.setEndpoint('http://example.com/api'); // Insecure endpoint
        req.setHeader('Authorization', 'Bearer 123SECRET'); // Hardcoded secret in header
        req.setMethod('POST');

        Http http = new Http();
        HttpResponse res = http.send(req);
    }

    // Dynamic SOQL injection vulnerability
    public void unsafeQuery(String userInput) {
        String query = 'SELECT Id, Name FROM Account WHERE Name = \'' + userInput + '\'';
        List<Account> accts = Database.query(query); // Unsafe dynamic SOQL
    }

    // Logging secrets
    public void logSecrets() {
        System.debug('Password is ' + password); // Sensitive logging
        System.debug('API Key is ' + apiKey);     // Sensitive logging
    }

    // Hardcoded assignment and passing secrets to endpoints
    public void callExternal() {
        String token = apiKey;                 // tracked secret variable
        HttpRequest req = new HttpRequest();
        req.setEndpoint(token);                // variable with secret
        req.setHeader('X-Token', token);       // variable with secret
    }

    // Multiple literals triggering hardcoded secret detection
    public void mixSecrets() {
        String secret1 = 'HELLO1234';
        String secret2 = 'WORLD5678';
        HttpRequest req = new HttpRequest();
        req.setEndpoint('callout:MyNamedCred'); // Named credential (safe)
        req.setHeader('X-Secret', secret2);     // ❌ triggers
    }

    // SOQL injection with variables
    public void searchAccounts(String nameInput) {
        String unsafe = 'SELECT Id FROM Account WHERE Name LIKE \'%' + nameInput + '%\'';
        List<Account> result = Database.query(unsafe); // triggers ApexTaintSoqlRule
    }

    // Logging in loops
    public void logInLoop() {
        List<String> secrets = new List<String>{'S1', 'S2', 'S3'};
        for(String s : secrets){
            System.debug('Logging secret: ' + s); // triggers ApexSensitiveLoggingRule
        }
    }

    // Combination of endpoint + SOQL + secret
    public void combinedAttack(String userInput) {
        String dynamicEndpoint = 'http://malicious.com/' + userInput; // triggers ApexInsecureEndpointRule
        HttpRequest req = new HttpRequest();
        req.setEndpoint(dynamicEndpoint);
        req.setHeader('Authorization', apiKey); // triggers hardcoded secrets rule

        String query = 'SELECT Id FROM Contact WHERE Email = \'' + userInput + '\''; // SOQL injection
        List<Contact> contacts = Database.query(query); // triggers ApexTaintSoqlRule
    }
}
