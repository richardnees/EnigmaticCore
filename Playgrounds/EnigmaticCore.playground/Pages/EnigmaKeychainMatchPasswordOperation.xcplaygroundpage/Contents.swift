import Cocoa
import Security
import EnigmaticCore

let baseEncodedString = "3Umfptbq4dplYstJY578esjrSyU84KSoEUHcKYf+o2cCovwzMQPuMZBifi5oeQxlhsd4k19ECnEo8Ts/QCuEAKp6pI8mhBsUW3TuLt2/FLqib1WJ2vbpv2ZZoypOLtWqTH8WeKV8+NY1RUF700oQZYRZNIVRMX7vPOFqss1TAyrU62g5XW3asfgPtje1RDACFBCdqmLdRy0jWZnL8ufqfNiEtUArFESRTH7us3jY9ou+OwL1FgKjwZaLzA0kX2WfLvzqrp9g/UkfWohjH7QvVzS/7eQ8Vj76V7cTKTZK40y8iuDbKooiQ5K/6BPdpICkLvnKDZpCRixOqv9Dr5UKVxFDCNYYUg66Fh17MYN7cmQipcpbbVNqwKYZY/aRKpNqoe3I1Y7Xp5H7RCgRa/QbETx61ZIhG1JApDvZlz+ngRzzzNmWjg1tC4k4CrD8+DyiJGvvEKZLjf6dDlZU4+/14b29NXCrmzCYrsgvIjOFwufWP1rp0O6FyWOna9x41OyKFB8ij1LtP/fUic7f59LWONQBk+Rpo6kGfQXHgGqIq940pb1ok6jpsHdon1M0j0vPBFEBdSGhIRTa83cINvNuN0HDZb1/z6f5o5pjzcLivLnFv9Ch476q73iWKgM9KzQjnzQVEbfsxULqyLZ1mH/uvw=="

let data = Data(base64Encoded: baseEncodedString)!

let queue = OperationQueue()
queue.qualityOfService = .background

let keychainMatchOperation = EnigmaKeychainMatchPasswordOperation()
keychainMatchOperation.label = "com.richardnees.EnigmaPlayground"
keychainMatchOperation.data = data
queue.addOperation(keychainMatchOperation)
queue.waitUntilAllOperationsAreFinished()

print("error:\n\(keychainMatchOperation.error)")
print("password:\n\(keychainMatchOperation.password as Any)")

