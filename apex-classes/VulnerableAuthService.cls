public class VulnerableAuthService {

    // -----------------------
    // 1. Global/Public methods without 'with sharing'
    // -----------------------
    public void publicMethod1() {
        Account a = [SELECT Id FROM Account LIMIT 1]; // violation: SObject access without sharing
        System.debug(a);
    }

    global void globalMethod1() {
        List<Contact> cs = [SELECT Id, Email FROM Contact]; // violation
    }

    public void publicMethod2() {
        insert new Account(Name='Test'); // violation
    }

    // -----------------------
    // 2. WebService / REST methods missing auth check
    // -----------------------
    @RestResource(urlMapping='/vuln1/*')
    global static void restMethod1() {
        List<Account> accounts = [SELECT Id FROM Account]; // violation
    }

    @WebService
    global static void wsMethod1() {
        Account a = [SELECT Id FROM Account LIMIT 1]; // violation
    }

    @RestResource(urlMapping='/vuln2/*')
    global static void restMethod2() {
        insert new Contact(LastName='Doe'); // violation
    }

    // -----------------------
    // 3. Multiple SObject operations without sharing
    // -----------------------
    public void modifyRecords() {
        List<Account> accs = [SELECT Id, Name FROM Account];
        for(Account a : accs){
            a.Name = 'Changed'; // violation
        }
        update accs; // violation

        delete [SELECT Id FROM Contact LIMIT 1]; // violation
    }

    global void globalBatchOp() {
        insert new Account(Name='Batch1'); // violation
        insert new Account(Name='Batch2'); // violation
    }
}
