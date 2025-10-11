using new_assistant.Core.DTOs;
using new_assistant.Core.Interfaces;

namespace new_assistant.Infrastructure.Services
{
    /// <summary>
    /// Сервис для управления состоянием поиска клиентов
    /// </summary>
    public class SearchStateService : ISearchStateService
    {
        private string _searchQuery = string.Empty;
        private ClientsSearchResponse? _searchResponse;
        private int _currentPage = 1;
        private bool _hasSearched = false;
        private bool _hasState = false;

        public void SaveSearchState(string searchQuery, ClientsSearchResponse? searchResponse, int currentPage, bool hasSearched)
        {
            _searchQuery = searchQuery;
            _searchResponse = searchResponse;
            _currentPage = currentPage;
            _hasSearched = hasSearched;
            _hasState = true;
        }

        public (string SearchQuery, ClientsSearchResponse? SearchResponse, int CurrentPage, bool HasSearched) GetSearchState()
        {
            return (_searchQuery, _searchResponse, _currentPage, _hasSearched);
        }

        public void ClearSearchState()
        {
            _searchQuery = string.Empty;
            _searchResponse = null;
            _currentPage = 1;
            _hasSearched = false;
            _hasState = false;
        }

        public bool HasSavedState()
        {
            return _hasState;
        }
    }
}
