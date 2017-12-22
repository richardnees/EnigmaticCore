import Cocoa
import Security
import EnigmaticCore

let password = "test"
let inputString = """
After being added to an operation queue, an NSOperation instance remains in that queue until it is explicitly canceled or finishes executing its task. Operations within the queue (but not yet executing) are themselves organized according to priority levels and inter-operation object dependencies and are executed accordingly. An application may create multiple operation queues and submit operations to any of them.
"""

let inputData = inputString.data(using: .utf8)

let queue = OperationQueue()
queue.qualityOfService = .background

let encryptDataTransform = EnigmaDataTransformOperation(transform: .encrypt, password: password)
encryptDataTransform.inputData = inputData
queue.addOperation(encryptDataTransform)
queue.waitUntilAllOperationsAreFinished()

print("encryptDataTransform.outputData:\n\(encryptDataTransform.outputData?.base64EncodedString() as Any)")

let decryptDataTransform = EnigmaDataTransformOperation(transform: .decrypt, password: password)
decryptDataTransform.inputData = encryptDataTransform.outputData
queue.addOperation(decryptDataTransform)
queue.waitUntilAllOperationsAreFinished()

print("decryptDataTransform:\n\(decryptDataTransform.outputData as Any)")

guard let outputData = decryptDataTransform.outputData else {
    print("No output data")
    exit(1)
}

let outputString = String(data: outputData, encoding: .utf8)
print("outputString:\n\(outputString as Any)")

