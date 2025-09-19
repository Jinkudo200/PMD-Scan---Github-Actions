public class VulnerableAuthService {

    // -----------------------
    // Global/Public methods without 'with sharing'
    // -----------------------
    public void publicMethod1() {
        Account a = [SELECT Id FROM Account LIMIT 1]; // SObject access without sharing
    }

    global void globalMethod1() {
        List<Contact> cs = [SELECT Id, Email FROM Contact]; // violation
    }

    public void publicMethod2() {
        insert new Account(Name='Test'); // violation
    }

    // -----------------------
    // REST methods missing auth check
    // -----------------------
    @RestResource(urlMapping='/vuln1/*')
    global static void restMethod1() {
        List<Account> accounts = [SELECT Id FROM Account]; // violation
    }

    @RestResource(urlMapping='/vuln2/*')
    global static void restMethod2() {
        insert new Contact(LastName='Doe'); // violation
    }

    // -----------------------
    // Multiple SObject operations without sharing
    // -----------------------
    public void modifyRecords() {
        List<Account> accs = [SELECT Id, Name FROM Account];
        for(Account a : accs){
            a.Name = 'Changed';
        }
        update accs; 
        delete [SELECT Id FROM Contact LIMIT 1]; 
    }

    global void globalBatchOp() {
        insert new Account(Name='Batch1'); 
        insert new Account(Name='Batch2'); 
    }
}
