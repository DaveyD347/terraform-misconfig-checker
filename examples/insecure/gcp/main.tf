terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

variable "project" {
  type    = string
  default = "acme-dev-123456"
}

resource "google_storage_bucket" "public_site" {
  name     = "${var.project}-site"
  location = "US"
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.public_site.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_compute_firewall" "ssh" {
  name    = "allow-ssh"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22", "8080-8090"]
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "internal" {
  name          = "allow-internal"
  network       = "default"
  source_ranges = ["10.128.0.0/9"]

  allow {
    protocol = "all"
  }
}

resource "google_sql_database_instance" "main" {
  name             = "acme-pg"
  database_version = "POSTGRES_16"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = true

      authorized_networks {
        name  = "everyone"
        value = "0.0.0.0/0"
      }
    }
  }
}

resource "google_project_iam_member" "contractor" {
  project = var.project
  role    = "roles/editor"
  member  = "user:contractor@example.com"
}

resource "google_compute_instance" "worker" {
  name         = "worker-1"
  machine_type = "e2-small"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    network = "default"
  }

  service_account {
    scopes = ["cloud-platform"]
  }
}
