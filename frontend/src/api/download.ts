export function triggerArchiveDownload(
  archive: Blob,
  fileName: string,
): void {
  const objectUrl = URL.createObjectURL(archive)
  const anchor = document.createElement('a')
  try {
    anchor.href = objectUrl
    anchor.download = fileName
    anchor.hidden = true
    document.body.append(anchor)
    anchor.click()
  } finally {
    anchor.remove()
    URL.revokeObjectURL(objectUrl)
  }
}
