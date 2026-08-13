class CreateBindsOwnerButReadIsUnscoped {
  private final TaskRepository repository;

  CreateBindsOwnerButReadIsUnscoped(TaskRepository repository) {
    this.repository = repository;
  }

  Task create(String currentUserId, String name) {
    Task task = new Task();
    task.setUserId(currentUserId);
    task.setName(name);
    return repository.save(task);
  }

  Task read(String taskId) {
    return repository.findById(taskId).orElseThrow();
  }
}
