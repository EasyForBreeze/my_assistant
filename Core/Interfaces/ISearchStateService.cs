using new_assistant.Core.DTOs;

namespace new_assistant.Core.Interfaces
{
    /// <summary>
    /// Сервис для управления состоянием поиска клиентов
    /// </summary>
    public interface ISearchStateService
    {
        /// <summary>
        /// Сохранить состояние поиска
        /// </summary>
        void SaveSearchState(string searchQuery, ClientsSearchResponse? searchResponse, int currentPage, bool hasSearched);

        /// <summary>
        /// Получить сохраненное состояние поиска
        /// </summary>
        (string SearchQuery, ClientsSearchResponse? SearchResponse, int CurrentPage, bool HasSearched) GetSearchState();

        /// <summary>
        /// Очистить сохраненное состояние
        /// </summary>
        void ClearSearchState();

        /// <summary>
        /// Проверить, есть ли сохраненное состояние
        /// </summary>
        bool HasSavedState();
    }
}
