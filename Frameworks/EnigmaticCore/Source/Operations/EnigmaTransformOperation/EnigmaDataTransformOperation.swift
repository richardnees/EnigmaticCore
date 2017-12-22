import Foundation

public class EnigmaDataTransformOperation: EnigmaTransformOperation {
    public var inputData: Data?
    public var outputData: Data?

    public override func main() {
        guard let inputData = inputData else {
            error = EnigmaError.noData
            return
        }
        
        do {
            outputData = try Enigma().transform(transform, data: inputData, password: password)
        } catch let error {
            self.error = error
        }
    }
}
