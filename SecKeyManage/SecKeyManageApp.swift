//
//  SecKeyManageApp.swift
//  SecKeyManage
//


import SwiftUI

@main
struct SecKeyManageApp: App {
    let persistenceController = PersistenceController.shared

    var body: some Scene {
        WindowGroup {
            EncryptionSampleView()
                .environment(\.managedObjectContext, persistenceController.container.viewContext)
        }
    }
}
