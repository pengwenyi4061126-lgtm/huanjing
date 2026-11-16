param([Parameter(Mandatory = $true)][string]$IdentityPath)
$identity = Get-Content -LiteralPath $IdentityPath -Raw | ConvertFrom-Json
$defaults = [ordered]@{
    system_manufacturer = 'ASUSTeK COMPUTER INC.'
    system_product = 'PRIME B550M-K'
    system_version = 'System Version'
    board_manufacturer = 'ASUSTeK COMPUTER INC.'
    board_product = 'PRIME B550M-K'
    board_version = 'Rev X.0x'
    bios_vendor = 'American Megatrends Inc.'
    bios_version = '5.17'
    bios_release_date = '01/01/2024'
    processor_name = 'AMD Ryzen 3 3100 4-Core Processor'
    cpu_vendor = 'AuthenticAMD'
    cpu_identifier = 'AMD64 Family 23 Model 113 Stepping 0'
    gpu_name = 'NVIDIA GeForce GTX 1650'
    gpu_vendor = 'NVIDIA'
    gpu_pci_id = 'PCI\VEN_10DE&DEV_1F82&SUBSYS_1F8210DE&REV_A1'
    gpu_memory_mb = 4096
    gpu_driver_version = '31.0.15.3699'
    gpu_serial = '1321919076543'
    gpu_uuid = 'GPU-8f3c2a1e-5b7d-4c9a-9e2f-1a3b5c7d9e0f'
    memory_vendor = 'Samsung'
    memory_part = 'M378A1K43CB2-CRC'
    memory_total_mb = 16384
    memory_available_mb = 12288
    memory_module_mb = 8192
    memory_speed_mhz = 3200
    disk_total_gb = 512
    disk_free_gb = 256
    disk_model = 'WDC WDS500G2B0A-00SM50'
    nic_name = 'Realtek PCIe GbE Family Controller'
    nic_pci_id = 'PCI\VEN_10EC&DEV_8168&SUBSYS_86761043&REV_15'
    cpu_cores = 4
    cpu_logical = 8
    cpu_max_mhz = 3600
    l2_cache_kb = 2048
    l3_cache_kb = 16384
    display_width = 1920
    display_height = 1080
    display_refresh = 60
    hypervisor_present = $false
    tpm_present = $false
    volume_label = 'System'
    filesystem = 'NTFS'
    monitor_name = 'Dell U2419H'
    monitor_manufacturer = 'Dell'
    monitor_pnp_id = 'DEL41A9'
    monitor_edid_manufacturer = 0x10AC
    monitor_edid_product = 0x41A9
    hid_vendor_id = 0x046D
    hid_product_id = 0xC52B
    hid_version = 0x0111
    hid_manufacturer = 'Logitech'
    hid_product = 'USB Receiver'
    hid_usage_page = 0x01
    hid_usage = 0x02
    hid_input_report_bytes = 7
    hid_output_report_bytes = 0
    hid_feature_report_bytes = 0
    audio_endpoint_id = '{0.0.0.00000000}.{8f3c2a1e-5b7d-4c9a-9e2f-1a3b5c7d9e0f}'
    audio_friendly_name = 'Speakers (Realtek(R) Audio)'
    audio_interface_name = 'Realtek High Definition Audio'
    audio_endpoint_guid = '{8f3c2a1e-5b7d-4c9a-9e2f-1a3b5c7d9e0f}'
    audio_form_factor = 1
    opencl_name = 'NVIDIA GeForce GTX 1650'
    opencl_vendor = 'NVIDIA'
    opencl_version = 'OpenCL 3.0 CUDA'
    opencl_compute_units = 14
}
$added = 0
foreach ($key in $defaults.Keys) {
    $prop = $identity.PSObject.Properties[$key]
    if ($null -eq $prop -or [string]::IsNullOrWhiteSpace([string]$prop.Value)) {
        Add-Member -InputObject $identity -NotePropertyName $key -NotePropertyValue $defaults[$key] -Force
        ++$added
    }
}
$identity | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $IdentityPath -Encoding UTF8
Write-Output "restored_fields=$added"
