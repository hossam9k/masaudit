import Foundation
import Photos

struct Photo { let creationDate: Date }      // a model property, not the file API

func save(asset: PHAsset) {
    UserDefaults.standard.set(asset.creationDate, forKey: "lastAsset")
}
