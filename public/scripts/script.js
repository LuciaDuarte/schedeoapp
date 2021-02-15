$('#addRow').click(function() {
  var html = '';
  html += '<div id="inputFormRow">';
  html += '<div class="input-group mb-3">';
  html += '<input type="date" name="date[]" class="form-control m-input">';
  html += '<div class="input-group-append">';
  html +=
    '<button id="removeRow" type="button" class="btn btn-danger">Remove</button>';
  html += '</div>';
  html += '</div>';
  $('#newRow').append(html);
});

$(document).on('click', '#removeRow', function() {
  $(this)
    .closest('#inputFormRow')
    .remove();
});
