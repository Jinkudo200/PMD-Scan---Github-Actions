public class VulnerableService {

    // -----------------------
    // Hardcoded secrets / variables
    // -----------------------
    private String apiKey = 'APIKEY-1234567890-SECRET';        // 1: Hardcoded secret (field)
    private String password = 'P@ssw0rd!';                     // 2: Hardcoded secret (field)

    // multiple hardcoded tokens
    public void declareLiterals() {
        String k1 = 'TOKEN-abcdefghijklmnop';                 // 3
        String k2 = 'token-9876543210-XYZ';                   // 4
        String cred = 'Bearer ' + 'ABCD1234EFGH5678';         // 5 concatenation
        System.debug('declared secret ' + k1);                // logging secret (sensitive logging)
    }

    // -----------------------
    // Hardcoded endpoints & headers (Named Credentials enforcement)
    // -----------------------
    public void insecureHttpLiteral() {
        HttpRequest r1 = new HttpRequest();
        r1.setEndpoint('http://insecure.example.com/api');    // 6: insecure http (ApexInsecureEndpointRule)
        r1.setHeader('Authorization', 'Bearer ' + apiKey);    // 7: hardcoded header (literal + field)
        r1.setHeader('X-API-KEY', '1234-5678-SECRET');        // 8: hardcoded header literal
    }

    public void insecureHttpVariable() {
        String badEp = 'http://evil.example.com/' + 'path';   // 9: built endpoint
        HttpRequest r2 = new HttpRequest();
        r2.setEndpoint(badEp);                                // 10: setEndpoint with variable
        String headerVal = apiKey;
        r2.setHeader('Authorization', headerVal);             // 11: setHeader with tracked variable
    }

    public void namedCredentialOk() {
        HttpRequest r3 = new HttpRequest();
        // safe: named credential
        r3.setEndpoint('callout:My_Named_Cred');              // safe (should not trigger)
    }

    // -----------------------
    // Sensitive logging & monitoring
    // -----------------------
    public void loggingSecrets() {
        System.debug('password=' + password);                 // 12: sensitive logging
        System.debug('apiKey=' + apiKey);                     // 13
        // logging concatenated secret
        String s = 'prefix' + 'secret' + 'suffix';
        System.debug('concat:' + s);                          // 14
    }

    // -----------------------
    // Insecure deserialization (JSON) - multiple variants
    // -----------------------
    public void insecureDeserializeFromRest() {
        // emulate reading from RestContext or request body
        // This code style triggers the InsecureDeserializationRule when passed untrusted source
        String body = RestContext.request != null ? RestContext.request.requestBody.toString() : '{"ok":1}';
        // Unsafe direct deserialization
        Object o1 = JSON.deserializeUntyped(body);            // 15: insecure deserialization (untyped)
        Map<String,Object> m1 = (Map<String,Object>) JSON.deserializeUntyped(body); // 16
    }

    public void insecureDeserializeFromParam(String jsonParam) {
        Object o2 = JSON.deserialize(jsonParam, Object.class); // 17: insecure if jsonParam unvalidated
    }

    public void insecureDeserializeFromHttp(HttpRequest req) {
        String b = req.getBody();
        Object o3 = JSON.deserializeUntyped(b);               // 18
    }

    // -----------------------
    // SOQL injection tests (dynamic queries)
    // -----------------------
    public void unsafeQueryInline(String nameInput) {
        // direct concatenation into dynamic SOQL
        String q = 'SELECT Id, Name FROM Account WHERE Name = \'' + nameInput + '\''; // 19
        List<Account> a = Database.query(q);                    // 20: dynamic SOQL (ApexTaintSoqlRule)
    }

    public List<Contact> unsafeQueryVar(String email) {
        String where = 'Email = \'' + email + '\'';
        String query = 'SELECT Id, Email FROM Contact WHERE ' + where; // 21
        return (List<Contact>) Database.query(query);          // 22
    }

    public void unsafeQueryConcat(String part1, String part2) {
        String q = 'SELECT Id FROM Opportunity WHERE Description LIKE \'%' + (part1 + part2) + '%\''; // 23
        List<Opportunity> ops = Database.query(q);            // 24
    }

    // safe-ish: escaped/validated example (should not trigger if properly sanitized)
    public void safeQuery(String name) {
        String escaped = String.escapeSingleQuotes(name);
        String q = 'SELECT Id FROM Account WHERE Name = \'' + escaped + '\'';
        List<Account> ok = Database.query(q);                 // safe when escaped
    }

    // -----------------------
    // Command injection / schedule / cron / enqueue / executeBatch
    // -----------------------
    public void scheduleWithUserInput(String cronPart) {
        // constructing a cron expression from untrusted input
        String cron = '0 0 ' + cronPart + ' * * ?';           // 25: cron built from user input
        System.schedule('job-' + cronPart, cron, new MySched()); // 26: System.schedule with tainted cron (ApexCommandScheduleInjectionRule)
    }

    public void enqueueJobWithInput(String jobName) {
        // using jobName that may be user-controlled
        System.enqueueJob(new MyQueueable(jobName));          // 27: enqueue with tainted input
    }

    public void executeBatchWithInput(List<SObject> records, String batchName) {
        Database.executeBatch(new MyBatch(records, batchName)); // 28: executeBatch with name from input
    }

    // -----------------------
    // Combine many issues in one method to fire multiple rules
    // -----------------------
    public void combinedAttack(String userInput, String jsonParam, HttpRequest extReq) {
        // dynamic endpoint
        String dyn = 'http://' + userInput + '/api';          // 29
        extReq.setEndpoint(dyn);                              // 30

        // dynamic header includes secret variable
        extReq.setHeader('Authorization', 'Bearer ' + password); // 31

        // deserialization from untrusted param
        Object bad = JSON.deserializeUntyped(jsonParam);       // 32

        // dynamic SOQL
        String q = 'SELECT Id FROM Contact WHERE Name = \'' + userInput + '\'';
        List<Contact> cs = Database.query(q);                 // 33

        // logging secrets
        System.debug('attack dump: ' + password);             // 34
    }
}
