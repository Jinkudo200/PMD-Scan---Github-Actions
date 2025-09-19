public class VulnerableDeprecatedService {

    public void triggerDeprecatedApis() {
        // -----------------------
        // Deprecated Crypto APIs
        // -----------------------
        Blob digest = Crypto.generateDigest('SHA1', Blob.valueOf('test')); // 1
        Blob encrypted = Crypto.encryptWithManagedIV('AES128', Blob.valueOf('secret')); // 2

        // -----------------------
        // Deprecated Http / Database
        // -----------------------
        HttpRequest req = new HttpRequest();
        req.setEndpoint('https://example.com');
        req.setMethod('GET');
        Http http = new Http();
        HttpResponse resp = http.send(req); // 3: deprecated Http.send

        List<Id> deletedIds = Database.emptyRecycleBin(new List<Id>{'001000000000001'}); // 4

        // -----------------------
        // Fake deprecated job enqueue
        // -----------------------
        System.enqueueJobLegacy(new MyQueueableJob()); // 5

        // -----------------------
        // Combined calls
        // -----------------------
        Blob digest2 = Crypto.generateDigest('MD5', Blob.valueOf('another')); // 6
        HttpResponse resp2 = http.send(req); // 7

        // -----------------------
        // Safe call (should NOT trigger)
        // -----------------------
        String safe = String.valueOf('safe'); // Safe, does not trigger
    }
}
