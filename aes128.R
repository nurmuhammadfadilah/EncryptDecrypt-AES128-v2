library(shiny)
library(shinyjs)
library(openssl)

# Function for Encryption
encrypt_file <- function(file_path, key) {
  file_data <- readBin(file_path, what = "raw", n = file.info(file_path)$size)
  key <- charToRaw(key)
  iv <- rand_bytes(16)
  encrypted_data <- aes_cbc_encrypt(file_data, key, iv)
  return(c(iv, encrypted_data))
}

# Function for Decryption
decrypt_file <- function(file_path, key) {
  file_data <- readBin(file_path, what = "raw", n = file.info(file_path)$size)
  iv <- file_data[1:16]
  encrypted_data <- file_data[-(1:16)]
  key <- charToRaw(key)
  decrypted_data <- aes_cbc_decrypt(encrypted_data, key, iv)
  return(decrypted_data)
}

# UI
ui <- fluidPage(
  useShinyjs(), # Enable shinyjs
  
  tags$head(
    tags$style(HTML("
      body { font-family: Arial, sans-serif; background-color: #f9f9f9; }
      .container { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; }
      .box { border: 2px solid #ddd; padding: 20px; border-radius: 10px; width: 400px; background-color: white; }
      .btn-primary { background-color: #6200EE; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; }
      .btn-center { display: flex; justify-content: center; gap: 20px; }
      .error { color: red; font-size: 12px; }
      .hidden { display: none; }
      .file-info { font-size: 12px; color: #555; margin-top: 10px; }
    "))
  ),

  tags$div(
    style = "display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; margin-bottom: 10px; padding: 2px; width: 100%;",
    tags$h2("AES128 File Encryption & Decryption", style = "margin: 0; font-weight: bold; color: #0047AB;"),
    tags$img(src = "https://upload.wikimedia.org/wikipedia/commons/6/68/LOGO_UEU_BY_ASU-06.png", 
             height = "80px", style = "margin-left: 15px;")
  ),
  hr(),
  div(class = "container",
      h2("🔒 File Encrypt and Decrypt Tool"),
      div(class = "btn-center",
          actionButton("encrypt_btn", "Encrypt File", class = "btn-primary"),
          actionButton("decrypt_btn", "Decrypt File", class = "btn-primary")
      ),
      br(),
      
      # Encrypt Section
      div(id = "encrypt_section",
          div(class = "box",
              h3("Step 1: Upload File"),
                   p("Pilih file yang ingin dienkripsi (PDF, Word, Excel, PNG, JPG, TIFF)."),
              fileInput("enc_file", "Choose a file:", accept = c(".pdf", ".docx", ".png", ".jpg", ".tiff")),
              textOutput("file_error"),
              div(class = "file-info", textOutput("enc_file_info")),
              hidden(div(id = "enc_step2",
                         h3("Step 2: Enter Key"),
                         tags$ol(
                              tags$li("Masukkan kunci enkripsi sepanjang 16 karakter."),
                              tags$li("Klik tombol 'Enkripsi' untuk memulai proses."),
                            ),
                         textInput("enc_password", "Enter 16-character password:", value = "KUNCI-KELOMPOK-1"),
                         textOutput("key_error"),
                         actionButton("encrypt_action_btn", "Encrypt File", class = "btn-primary")
              )),
              hidden(div(id = "enc_step3",
                         h3("Step 3: Download Encrypted File"),
                         p("Unduh file hasil enkripsi setelah selesai."),
                         downloadButton("enc_download", "Download Encrypted File", class = "btn-primary"),
                         div(class = "file-info", textOutput("enc_runtime"))
              ))
          )
      ),
      
      # Decrypt Section
      div(id = "decrypt_section",
          div(class = "box",
              h3("Step 1: Upload Encrypted File"),
              p("Pilih file terenkripsi (format '.enc')."),
              fileInput("dec_file", "Choose a file (.enc):", accept = ".enc"),
              textOutput("dec_file_error"),
              div(class = "file-info", textOutput("dec_file_info")),
              hidden(div(id = "dec_step2",
                         h3("Step 2: Enter Key"),
                         tags$ol(
                            tags$li("Masukkan kunci dekripsi yang sesuai."),
                            tags$li("Klik tombol 'Dekripsi' untuk memulai proses."),
                            ),
                         textInput("dec_password", "Enter 16-character password:", value = "KUNCI-KELOMPOK-1"),
                         textOutput("dec_key_error"),
                         actionButton("decrypt_action_btn", "Decrypt File", class = "btn-primary")
              )),
              hidden(div(id = "dec_step3",
                         h3("Step 3: Download Decrypted File"),
                         p("Unduh file hasil dekripsi setelah selesai."),
                         downloadButton("dec_download", "Download Decrypted File", class = "btn-primary"),
                         div(class = "file-info", textOutput("dec_runtime"))
              ))
          )
      )
  )
)

# Server
server <- function(input, output, session) {
  
  # Initially hide both sections
  hide("encrypt_section")
  hide("decrypt_section")
  
  # Show Encrypt Section when Encrypt Button is clicked
  observeEvent(input$encrypt_btn, {
    show("encrypt_section")
    hide("decrypt_section")
  })
  
  # Show Decrypt Section when Decrypt Button is clicked
  observeEvent(input$decrypt_btn, {
    show("decrypt_section")
    hide("encrypt_section")
  })
  
  # Display File Info for Encryption
  observe({
    req(input$enc_file)
    file_info <- input$enc_file
    output$enc_file_info <- renderText({
      paste0("File Name: ", file_info$name, ", Size: ", format(file_info$size, big.mark = ","), " bytes")
    })
  })
  
  # Encrypt Process
  observe({
    req(input$enc_file)
    file_size <- input$enc_file$size / (1024^2) # Size in MB
    file_ext <- tools::file_ext(input$enc_file$name)
    valid_ext <- c("pdf", "docx", "png", "jpg", "tiff")
    
    if (file_size > 1) {
      output$file_error <- renderText("⚠️ File melebihi 1MB.")
      hide("enc_step2")
    } else if (!(file_ext %in% valid_ext)) {
      output$file_error <- renderText("⚠️ File tidak didukung.")
      hide("enc_step2")
    } else {
      output$file_error <- renderText("")
      show("enc_step2")
    }
  })
  
  observeEvent(input$encrypt_action_btn, {
    req(input$enc_password)
    if (nchar(input$enc_password) != 16) {
      output$key_error <- renderText("⚠️ Kunci harus 16 karakter.")
      return()
    }
    output$key_error <- renderText("")
    
    runtime <- system.time({
      encrypted <- encrypt_file(input$enc_file$datapath, input$enc_password)
      output$enc_download <- downloadHandler(
        filename = function() { paste0(input$enc_file$name, ".enc") },
        content = function(file) { writeBin(encrypted, file) }
      )
    })
    show("enc_step3")
    output$enc_runtime <- renderText({
      paste0("Runtime: ", round(runtime[3], 6), " seconds, Processed File Size: ", 
             format(length(encrypted), big.mark = ","), " bytes")
    })
  })
  
  # Display File Info for Decryption
  observe({
    req(input$dec_file)
    file_info <- input$dec_file
    output$dec_file_info <- renderText({
      paste0("File Name: ", file_info$name, ", Size: ", format(file_info$size, big.mark = ","), " bytes")
    })
  })
  
  # Decrypt Process
  observe({
    req(input$dec_file)
    file_size <- input$dec_file$size / (1024^2) # Size in MB
    file_ext <- tools::file_ext(input$dec_file$name)
    
    if (file_size <= 0) {
      output$dec_file_error <- renderText("⚠️ Please upload a valid encrypted file.")
      hide("dec_step2")
    } else if (file_ext != "enc") {
      output$dec_file_error <- renderText("⚠️ File extension should be .enc.")
      hide("dec_step2")
    } else {
      output$dec_file_error <- renderText("")
      show("dec_step2")
    }
  })
  
  observeEvent(input$decrypt_action_btn, {
    req(input$dec_password)
    if (nchar(input$dec_password) != 16) {
      output$dec_key_error <- renderText("⚠️ Key must be 16 characters long.")
      return()
    }
    output$dec_key_error <- renderText("")
    
    runtime <- system.time({
      decrypted <- tryCatch({
        decrypt_file(input$dec_file$datapath, input$dec_password)
      }, error = function(e) {
        showNotification("⚠️ Invalid key or corrupted file!", type = "error")
        return(NULL)
      })
      if (!is.null(decrypted)) {
        output$dec_download <- downloadHandler(
          filename = function() { gsub("\\.enc$", "", input$dec_file$name) },
          content = function(file) { writeBin(decrypted, file) }
        )
      }
    })
    show("dec_step3")
    output$dec_runtime <- renderText({
      paste0("Runtime: ", round(runtime[3], 6), " seconds, Processed File Size: ", 
             format(length(decrypted), big.mark = ","), " bytes")
    })
  })
}

shinyApp(ui, server)
