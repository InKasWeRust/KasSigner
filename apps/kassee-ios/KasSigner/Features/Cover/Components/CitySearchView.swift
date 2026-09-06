import SwiftUI

struct CitySearchView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var model: WeatherCoverModel
    @State private var query = ""

    let select: (WeatherLocation) -> Void

    var body: some View {
        NavigationStack {
            List(model.searchResults) { location in
                Button {
                    select(location)
                } label: {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(location.name).font(.headline)
                        Text(location.displayName)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }
                .foregroundStyle(.primary)
            }
            .overlay {
                if model.isSearching {
                    ProgressView()
                } else if query.count >= 2 && model.searchResults.isEmpty {
                    ContentUnavailableView.search(text: query)
                }
            }
            .navigationTitle("Choose City")
            .navigationBarTitleDisplayMode(.inline)
            .searchable(text: $query, prompt: "City or postal code")
            .onChange(of: query) { _, newValue in
                Task {
                    try? await Task.sleep(for: .milliseconds(350))
                    guard !Task.isCancelled, query == newValue else { return }
                    await model.searchCities(newValue)
                }
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }
}
