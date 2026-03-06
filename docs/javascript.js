document.addEventListener('DOMContentLoaded', () => {
    const after   = 'copied'
    const before  = 'copy'
    const codes   = document.querySelectorAll('pre > code')
    const timeout = 1000

    codes.forEach(code => {
        const error   = () => alert('failed to copy text to clipboard')
        const link    = document.createElement('a')
        const ok      = () => { link.textContent = after; setTimeout(reset, timeout); }
        const reset   = () => link.textContent = before
        const text    = code.textContent.trim()

        const click = event => {
            event.preventDefault()
            navigator.clipboard.writeText(text).then(ok).catch(error)
        }

        link.href        = '#'
        link.textContent = before

        link.addEventListener('click', click)
        code.parentNode.appendChild(link)
    })
})




// vim: et fenc=utf-8 nobomb sts=4 sw=4 ts=4
