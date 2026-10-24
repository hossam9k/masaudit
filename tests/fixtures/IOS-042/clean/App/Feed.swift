import Foundation

func parse(_ data: Data) {
    let parser = XMLParser(data: data)
    parser.shouldResolveExternalEntities = false
    parser.parse()
}
