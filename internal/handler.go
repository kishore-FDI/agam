package internal

import (
    "encoding/json"
    "net/http"

    "gorm.io/gorm"
)

func CreateUserHandler(db *gorm.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {

        // Parse incoming JSON body
        var input User
        if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
            http.Error(w, "invalid JSON body", http.StatusBadRequest)
            return
        }

        // Call service layer
        user, err := CreateUser(db, input)
        if err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        // Respond with created user (but avoid sending password hash)
        user.Password = "" // never leak hashes

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        json.NewEncoder(w).Encode(user)
    }
}

func CreateVaultHandler(db *gorm.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var input Vault
        if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
            http.Error(w, "invalid JSON body", http.StatusBadRequest)
            return
        }

        vault, err := CreateVault(db, input)
        if err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        json.NewEncoder(w).Encode(vault)
    }
}

func UpdateVaultHandler(db *gorm.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Expect: /vaults/{vaultID}?user={userID}
        vaultIDStr := r.URL.Query().Get("vault_id")
        userIDStr := r.URL.Query().Get("user_id")

        if vaultIDStr == "" || userIDStr == "" {
            http.Error(w, "vault_id and user_id are required", http.StatusBadRequest)
            return
        }

        vaultID, err := uuid.Parse(vaultIDStr)
        if err != nil {
            http.Error(w, "invalid vault_id", http.StatusBadRequest)
            return
        }

        userID, err := uuid.Parse(userIDStr)
        if err != nil {
            http.Error(w, "invalid user_id", http.StatusBadRequest)
            return
        }

        // Parse JSON body for updates
        updates := map[string]interface{}{}
        if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
            http.Error(w, "invalid JSON body", http.StatusBadRequest)
            return
        }

        updatedVault, err := UpdateVault(db, vaultID, userID, updates)
        if err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(updatedVault)
    }
}

func DeleteVaultHandler(db *gorm.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        vaultIDStr := r.URL.Query().Get("vault_id")
        userIDStr := r.URL.Query().Get("user_id")

        if vaultIDStr == "" || userIDStr == "" {
            http.Error(w, "vault_id and user_id are required", http.StatusBadRequest)
            return
        }

        vaultID, err := uuid.Parse(vaultIDStr)
        if err != nil {
            http.Error(w, "invalid vault_id", http.StatusBadRequest)
            return
        }

        userID, err := uuid.Parse(userIDStr)
        if err != nil {
            http.Error(w, "invalid user_id", http.StatusBadRequest)
            return
        }

        if err := DeleteVault(db, vaultID, userID); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        w.WriteHeader(http.StatusNoContent)
    }
}

func ListVaultsHandler(db *gorm.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        userIDStr := r.URL.Query().Get("user_id")
        if userIDStr == "" {
            http.Error(w, "user_id is required", http.StatusBadRequest)
            return
        }

        userID, err := uuid.Parse(userIDStr)
        if err != nil {
            http.Error(w, "invalid user_id", http.StatusBadRequest)
            return
        }

        vaults, err := ListVaults(db, userID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(vaults)
    }
}
